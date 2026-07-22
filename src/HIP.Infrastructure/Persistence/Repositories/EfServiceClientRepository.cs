using HIP.Application.ServiceClients;
using HIP.Domain.Audit;
using HIP.Domain.ServiceClients;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists service clients as owner-partitioned encrypted aggregates while retaining one
/// insert-only global client-ID binding for authentication lookup.
/// </summary>
public sealed class EfServiceClientRepository(HipRecordStore store) : IServiceClientRepository
{
    internal const string OwnerPartitionPrefix = "service-client-v1:";
    internal const string ClientBindingPartition = "service-client-v1:client-id-binding";
    internal const string AuditPartition = "audit-log";

    private const int BindingSchemaVersion = 1;

    /// <inheritdoc />
    public async Task<ServiceClientRegistration?> GetAsync(
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ServiceClientRepositoryCursor.IsCanonicalClientId(clientId))
        {
            throw new ArgumentException("The service-client identifier is invalid.", nameof(clientId));
        }

        var binding = await store.GetEncryptedAsync<ServiceClientOwnerBinding>(
                ClientBindingPartition,
                clientId,
                cancellationToken)
            .ConfigureAwait(false);
        if (binding is null)
        {
            return null;
        }

        ValidateStoredBinding(binding, clientId);
        var stored = await GetStoredRegistrationAsync(
                binding.OwnerScopeId,
                clientId,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            throw new InvalidOperationException("Persisted service-client binding data has no matching aggregate.");
        }

        return stored;
    }

    /// <inheritdoc />
    public async Task<ServiceClientRepositoryPage> ListByOwnerAsync(
        string ownerScopeId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken) =>
        await ListByOwnerAsync([ownerScopeId], cursor, pageSize, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<ServiceClientRepositoryPage> ListByOwnerAsync(
        IReadOnlyList<string> ownerScopeIds,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ServiceClientRepositoryCursor.ValidateOwnerScopeIds(ownerScopeIds);
        if (pageSize is < 1 or > ServiceClientRepositoryPage.MaximumPageSize)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize),
                $"Page size must be between 1 and {ServiceClientRepositoryPage.MaximumPageSize}.");
        }

        var afterClientId = cursor is null
            ? null
            : ServiceClientRepositoryCursor.Decode(cursor, ownerScopeIds[0]);
        var candidates = new List<ServiceClientRegistration>(ownerScopeIds.Count * pageSize);
        var partitionHasMore = false;
        foreach (var ownerScopeId in ownerScopeIds)
        {
            var partitionPage = await store.ListEncryptedPageAsync<ServiceClientRegistration>(
                    OwnerPartition(ownerScopeId),
                    afterClientId,
                    pageSize,
                    cancellationToken)
                .ConfigureAwait(false);
            foreach (var item in partitionPage.Items)
            {
                ValidateStoredRegistration(
                    item.Record,
                    ownerScopeId,
                    item.Id,
                    item.AggregateVersion);
                candidates.Add(item.Record);
            }

            partitionHasMore |= partitionPage.NextCursor is not null;
        }

        var ordered = candidates
            .OrderBy(registration => registration.ClientId, StringComparer.Ordinal)
            .ToArray();
        if (ordered.Select(registration => registration.ClientId)
            .Distinct(StringComparer.Ordinal)
            .Count() != ordered.Length)
        {
            throw new InvalidOperationException(
                "Persisted service-client owner partitions contain a duplicate client binding.");
        }

        var items = ordered.Take(pageSize).ToArray();
        var hasMore = ordered.Length > pageSize || partitionHasMore;
        var nextCursor = hasMore && items.Length > 0
            ? ServiceClientRepositoryCursor.Encode(ownerScopeIds[0], items[^1].ClientId)
            : null;
        return new ServiceClientRepositoryPage(
            items,
            nextCursor);
    }

    /// <inheritdoc />
    public async Task<ServiceClientSaveOutcome> TrySaveAsync(
        ServiceClientTransitionBatch transition,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ServiceClientTransitionValidator.ValidateTransition(transition);
        var registration = transition.Registration;
        ServiceClientRegistration? previous;

        if (transition.ExpectedAggregateVersion == 0)
        {
            var existingInOwnerPartition = await GetStoredRegistrationAsync(
                    registration.OwnerScopeId,
                    registration.ClientId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (existingInOwnerPartition is not null)
            {
                return ServiceClientSaveOutcome.VersionConflict;
            }

            previous = null;
        }
        else
        {
            previous = await GetAsync(registration.ClientId, cancellationToken).ConfigureAwait(false);
            if (previous is null ||
                !string.Equals(previous.OwnerScopeId, registration.OwnerScopeId, StringComparison.Ordinal) ||
                previous.AggregateVersion != transition.ExpectedAggregateVersion)
            {
                return ServiceClientSaveOutcome.VersionConflict;
            }
        }

        ServiceClientTransitionValidator.ValidateDelta(previous, transition);
        var relatedWrites = new List<HipRelatedRecordWrite>(transition.AuditEntries.Count + 1);
        if (previous is null)
        {
            relatedWrites.Add(new HipRelatedRecordWrite<ServiceClientOwnerBinding>(
                ClientBindingPartition,
                registration.ClientId,
                new ServiceClientOwnerBinding(
                    BindingSchemaVersion,
                    registration.ClientId,
                    registration.OwnerScopeId)));
        }

        relatedWrites.AddRange(transition.AuditEntries.Select(audit =>
            (HipRelatedRecordWrite)new HipRelatedRecordWrite<AuditLogEntry>(
                AuditPartition,
                audit.AuditLogId,
                audit)));

        var saved = await store.TrySaveVersionedWithRelatedRecordsAsync(
                OwnerPartition(registration.OwnerScopeId),
                registration.ClientId,
                registration,
                transition.ExpectedAggregateVersion,
                registration.AggregateVersion,
                relatedWrites,
                cancellationToken)
            .ConfigureAwait(false);
        return saved
            ? ServiceClientSaveOutcome.Succeeded
            : ServiceClientSaveOutcome.VersionConflict;
    }

    private async Task<ServiceClientRegistration?> GetStoredRegistrationAsync(
        string ownerScopeId,
        string clientId,
        CancellationToken cancellationToken)
    {
        var stored = await store.GetEncryptedVersionedAsync<ServiceClientRegistration>(
                OwnerPartition(ownerScopeId),
                clientId,
                cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        ValidateStoredRegistration(
            stored.Value.Record,
            ownerScopeId,
            clientId,
            stored.Value.AggregateVersion);
        return stored.Value.Record;
    }

    private static void ValidateStoredBinding(ServiceClientOwnerBinding binding, string expectedClientId)
    {
        if (binding.SchemaVersion != BindingSchemaVersion ||
            !string.Equals(binding.ClientId, expectedClientId, StringComparison.Ordinal) ||
            !ServiceClientRepositoryCursor.IsCanonicalClientId(binding.ClientId))
        {
            throw new InvalidOperationException("Persisted service-client binding data is invalid.");
        }

        try
        {
            ServiceClientRepositoryCursor.ValidateOwnerScopeId(binding.OwnerScopeId);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException("Persisted service-client binding data is invalid.", exception);
        }
    }

    private static void ValidateStoredRegistration(
        ServiceClientRegistration registration,
        string expectedOwnerScopeId,
        string expectedClientId,
        long databaseAggregateVersion)
    {
        if (registration is null ||
            !string.Equals(registration.OwnerScopeId, expectedOwnerScopeId, StringComparison.Ordinal) ||
            !string.Equals(registration.ClientId, expectedClientId, StringComparison.Ordinal) ||
            registration.AggregateVersion != databaseAggregateVersion)
        {
            throw new InvalidOperationException("Persisted service-client aggregate data is invalid.");
        }
    }

    private static string OwnerPartition(string ownerScopeId)
    {
        ServiceClientRepositoryCursor.ValidateOwnerScopeId(ownerScopeId);
        return OwnerPartitionPrefix + ownerScopeId;
    }

    /// <summary>Encrypted insert-only lookup from a global client ID to its owner partition.</summary>
    internal sealed record ServiceClientOwnerBinding
    {
        /// <summary>Creates the stable version-one binding payload used by authentication lookup.</summary>
        [System.Text.Json.Serialization.JsonConstructor]
        public ServiceClientOwnerBinding(int schemaVersion, string clientId, string ownerScopeId)
        {
            SchemaVersion = schemaVersion;
            ClientId = clientId;
            OwnerScopeId = ownerScopeId;
        }

        public int SchemaVersion { get; }

        public string ClientId { get; }

        public string OwnerScopeId { get; }
    }
}
