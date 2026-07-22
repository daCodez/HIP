using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists encrypted signing-key ring snapshots with PostgreSQL compare-and-swap semantics.
/// </summary>
/// <param name="store">Encrypted HIP record store with database-filtered versioned writes.</param>
public sealed class EfSigningKeyLifecycleRepository(HipRecordStore store) : ISigningKeyLifecycleRepository
{
    private const string Partition = "signing-key-ring";
    private const string IdentityPartition = "identity";
    private const string AuditPartition = "audit-log";

    /// <inheritdoc />
    public async Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        var storedRecord = await store.GetEncryptedVersionedAsync<SigningKeyRing>(
                Partition,
                identityId,
                cancellationToken)
            .ConfigureAwait(false);
        if (storedRecord is null)
        {
            return null;
        }

        var (keyRing, aggregateVersion) = storedRecord.Value;
        if (keyRing.Version != aggregateVersion)
        {
            throw new InvalidOperationException(
                "Persisted signing-key lifecycle version metadata did not match the encrypted aggregate.");
        }

        if (!string.Equals(keyRing.IdentityId, identityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Persisted signing-key lifecycle data did not match the requested identity.");
        }

        return keyRing;
    }

    /// <inheritdoc />
    public async Task<HipIdentity?> GetRegisteredIdentityAsync(
        string identityId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        var identity = await store.GetEncryptedAsync<HipIdentity>(
                IdentityPartition,
                identityId,
                cancellationToken)
            .ConfigureAwait(false);
        if (identity is not null &&
            !string.Equals(identity.IdentityId, identityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Persisted HIP identity data did not match the requested identity.");
        }

        return identity;
    }

    /// <inheritdoc />
    public Task<bool> TryRegisterIdentityAsync(
        IdentitySigningKeyRegistrationBatch registrationBatch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registrationBatch);
        var transition = registrationBatch.LifecycleTransition;
        var keyRing = transition.KeyRing;
        var relatedWrites = new List<HipRelatedRecordWrite>(transition.AuditEntries.Count + 1)
        {
            new HipRelatedRecordWrite<HipIdentity>(
                IdentityPartition,
                registrationBatch.Identity.IdentityId,
                registrationBatch.Identity)
        };
        relatedWrites.AddRange(transition.AuditEntries.Select(entry =>
            (HipRelatedRecordWrite)new HipRelatedRecordWrite<HIP.Domain.Audit.AuditLogEntry>(
                AuditPartition,
                entry.AuditLogId,
                entry)));

        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            keyRing.IdentityId,
            keyRing,
            transition.ExpectedVersion,
            keyRing.Version,
            relatedWrites,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> TrySaveAsync(
        SigningKeyLifecycleTransitionBatch transitionBatch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transitionBatch);
        var keyRing = transitionBatch.KeyRing;
        var auditWrites = transitionBatch.AuditEntries
            .Select(entry => new HipRelatedRecordWrite<HIP.Domain.Audit.AuditLogEntry>(
                AuditPartition,
                entry.AuditLogId,
                entry))
            .ToArray();

        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            keyRing.IdentityId,
            keyRing,
            transitionBatch.ExpectedVersion,
            keyRing.Version,
            auditWrites,
            cancellationToken);
    }
}
