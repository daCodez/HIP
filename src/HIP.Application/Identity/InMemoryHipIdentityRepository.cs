using System.Collections.Concurrent;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public sealed class InMemoryHipIdentityRepository : IHipIdentityRepository
{
    private readonly ConcurrentDictionary<string, HipIdentity> _identities = new(StringComparer.OrdinalIgnoreCase);

    public Task<HipIdentity> SaveAsync(HipIdentity identity, CancellationToken cancellationToken)
    {
        _identities[identity.IdentityId] = identity;
        return Task.FromResult(identity);
    }

    public Task<HipIdentity?> GetAsync(string identityId, CancellationToken cancellationToken)
    {
        _identities.TryGetValue(identityId, out var identity);
        return Task.FromResult(identity);
    }

    public Task<bool> TryUpdateAsync(
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

        return Task.FromResult(_identities.TryUpdate(expected.IdentityId, updated, expected));
    }
}
