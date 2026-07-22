using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Stores immutable signing-key ring snapshots and audit evidence in one in-memory commit boundary.
/// </summary>
public sealed class InMemorySigningKeyLifecycleRepository :
    ISigningKeyLifecycleRepository,
    IHipIdentityRepository,
    IAuditLogRepository
{
    private readonly Dictionary<string, HipIdentity> identities = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SigningKeyRing> keyRings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, AuditLogEntry> auditEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    /// <inheritdoc />
    public Task<HipIdentity?> GetRegisteredIdentityAsync(
        string identityId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId);
        cancellationToken.ThrowIfCancellationRequested();

        lock (gate)
        {
            identities.TryGetValue(identityId, out var identity);
            return Task.FromResult(identity);
        }
    }

    /// <inheritdoc />
    public Task<bool> TryRegisterIdentityAsync(
        IdentitySigningKeyRegistrationBatch registrationBatch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registrationBatch);
        cancellationToken.ThrowIfCancellationRequested();

        lock (gate)
        {
            var identity = registrationBatch.Identity;
            var transition = registrationBatch.LifecycleTransition;
            if (identities.ContainsKey(identity.IdentityId) ||
                keyRings.ContainsKey(identity.IdentityId) ||
                transition.AuditEntries.Any(entry => auditEntries.ContainsKey(entry.AuditLogId)))
            {
                return Task.FromResult(false);
            }

            identities.Add(identity.IdentityId, identity);
            keyRings.Add(identity.IdentityId, transition.KeyRing);
            foreach (var entry in transition.AuditEntries)
            {
                auditEntries.Add(entry.AuditLogId, entry);
            }

            return Task.FromResult(true);
        }
    }

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

    Task<HipIdentity> IHipIdentityRepository.SaveAsync(
        HipIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            identities[identity.IdentityId] = identity;
        }

        return Task.FromResult(identity);
    }

    Task<HipIdentity?> IHipIdentityRepository.GetAsync(
        string identityId,
        CancellationToken cancellationToken) =>
        GetRegisteredIdentityAsync(identityId, cancellationToken);

    Task<bool> IHipIdentityRepository.TryUpdateAsync(
        HipIdentity expected,
        HipIdentity updated,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(updated);
        cancellationToken.ThrowIfCancellationRequested();
        if (expected.IdentityType != updated.IdentityType ||
            !string.Equals(expected.IdentityId, updated.IdentityId, StringComparison.Ordinal) ||
            !string.Equals(expected.DisplayName, updated.DisplayName, StringComparison.Ordinal) ||
            !string.Equals(expected.PublicKey, updated.PublicKey, StringComparison.Ordinal) ||
            !string.Equals(expected.KeyAlgorithm, updated.KeyAlgorithm, StringComparison.Ordinal) ||
            expected.CreatedAtUtc != updated.CreatedAtUtc ||
            !string.Equals(expected.ReputationTargetId, updated.ReputationTargetId, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "HIP verification-status updates cannot change canonical identity fields.",
                nameof(updated));
        }

        lock (gate)
        {
            if (!identities.TryGetValue(expected.IdentityId, out var current) || current != expected)
            {
                return Task.FromResult(false);
            }

            identities[expected.IdentityId] = updated;
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

    public Task<bool> TryCreateAsync(AuditLogEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult(auditEntries.TryAdd(entry.AuditLogId, entry));
        }
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
