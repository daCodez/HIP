using HIP.Domain.Audit;
using HIP.Domain.ServiceClients;

namespace HIP.Application.ServiceClients;

/// <summary>Process-local CAS repository used by focused tests and explicit development hosts.</summary>
public sealed class InMemoryServiceClientRepository : IServiceClientRepository
{
    private readonly Dictionary<string, ServiceClientRegistration> registrations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SortedSet<string>> ownerClientIds = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AuditLogEntry> auditEntries = new(StringComparer.Ordinal);
    private readonly object gate = new();

    public Task<ServiceClientRegistration?> GetAsync(
        string clientId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        lock (gate)
        {
            registrations.TryGetValue(clientId, out var registration);
            return Task.FromResult(registration);
        }
    }

    public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
        string ownerScopeId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken) =>
        ListByOwnerAsync([ownerScopeId], cursor, pageSize, cancellationToken);

    /// <inheritdoc />
    public Task<ServiceClientRepositoryPage> ListByOwnerAsync(
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

        lock (gate)
        {
            var afterClientId = cursor is null
                ? null
                : ServiceClientRepositoryCursor.Decode(cursor, ownerScopeIds[0]);
            var ids = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var ownerScopeId in ownerScopeIds)
            {
                if (ownerClientIds.TryGetValue(ownerScopeId, out var ownerIds))
                {
                    ids.UnionWith(ownerIds);
                }
            }

            var page = new List<ServiceClientRegistration>(pageSize + 1);
            foreach (var clientId in ids)
            {
                if (afterClientId is not null && string.CompareOrdinal(clientId, afterClientId) <= 0)
                {
                    continue;
                }

                page.Add(registrations[clientId]);
                if (page.Count > pageSize)
                {
                    break;
                }
            }

            var hasMore = page.Count > pageSize;
            if (hasMore)
            {
                page.RemoveAt(page.Count - 1);
            }

            var nextCursor = hasMore
                ? ServiceClientRepositoryCursor.Encode(ownerScopeIds[0], page[^1].ClientId)
                : null;
            return Task.FromResult(new ServiceClientRepositoryPage(page, nextCursor));
        }
    }

    public Task<ServiceClientSaveOutcome> TrySaveAsync(
        ServiceClientTransitionBatch transition,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ServiceClientTransitionValidator.ValidateTransition(transition);

        lock (gate)
        {
            var registration = transition.Registration;
            registrations.TryGetValue(registration.ClientId, out var previous);
            if (transition.ExpectedAggregateVersion == 0)
            {
                if (previous is not null)
                {
                    return Task.FromResult(ServiceClientSaveOutcome.VersionConflict);
                }
            }
            else if (previous is null || previous.AggregateVersion != transition.ExpectedAggregateVersion)
            {
                return Task.FromResult(ServiceClientSaveOutcome.VersionConflict);
            }

            ServiceClientTransitionValidator.ValidateDelta(previous, transition);
            if (transition.AuditEntries.Any(entry => auditEntries.ContainsKey(entry.AuditLogId)))
            {
                return Task.FromResult(ServiceClientSaveOutcome.VersionConflict);
            }

            registrations[registration.ClientId] = registration;
            if (previous is null)
            {
                if (!ownerClientIds.TryGetValue(registration.OwnerScopeId, out var ids))
                {
                    ids = new SortedSet<string>(StringComparer.Ordinal);
                    ownerClientIds.Add(registration.OwnerScopeId, ids);
                }

                ids.Add(registration.ClientId);
            }

            foreach (var audit in transition.AuditEntries)
            {
                auditEntries.Add(audit.AuditLogId, audit);
            }

            return Task.FromResult(ServiceClientSaveOutcome.Succeeded);
        }
    }

}
