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
}
