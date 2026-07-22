using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Stores immutable signing-key ring snapshots and audit evidence in one in-memory commit boundary.
/// </summary>
public sealed class InMemorySigningKeyLifecycleRepository : ISigningKeyLifecycleRepository, IAuditLogRepository
{
    private readonly Dictionary<string, SigningKeyRing> keyRings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AuditLogEntry> auditEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    /// <inheritdoc />
    public Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        cancellationToken.ThrowIfCancellationRequested();

        lock (gate)
        {
            keyRings.TryGetValue(identityId, out var keyRing);
            return Task.FromResult(keyRing);
        }
    }

    /// <inheritdoc />
    public Task<bool> TrySaveAsync(
        SigningKeyLifecycleTransitionBatch transitionBatch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transitionBatch);
        cancellationToken.ThrowIfCancellationRequested();

        lock (gate)
        {
            var keyRing = transitionBatch.KeyRing;
            var expectedVersion = transitionBatch.ExpectedVersion;
            if (expectedVersion == 0)
            {
                if (keyRings.ContainsKey(keyRing.IdentityId))
                {
                    return Task.FromResult(false);
                }
            }
            else if (!keyRings.TryGetValue(keyRing.IdentityId, out var current) ||
                     current.Version != expectedVersion)
            {
                return Task.FromResult(false);
            }

            if (transitionBatch.AuditEntries.Any(entry => auditEntries.ContainsKey(entry.AuditLogId)))
            {
                return Task.FromResult(false);
            }

            keyRings[keyRing.IdentityId] = keyRing;
            foreach (var entry in transitionBatch.AuditEntries)
            {
                auditEntries.Add(entry.AuditLogId, entry);
            }

            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            auditEntries[entry.AuditLogId] = entry;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<AuditLogEntry>>(auditEntries.Values.ToArray());
        }
    }
}
