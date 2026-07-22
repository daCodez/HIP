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
    private const string AuditPartition = "audit-log";

    /// <inheritdoc />
    public async Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        var keyRing = await store.GetEncryptedAsync<SigningKeyRing>(
                Partition,
                identityId,
                cancellationToken)
            .ConfigureAwait(false);
        if (keyRing is not null &&
            !string.Equals(keyRing.IdentityId, identityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Persisted signing-key lifecycle data did not match the requested identity.");
        }

        return keyRing;
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
