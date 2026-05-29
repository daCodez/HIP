using HIP.Application.Identity;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfHipIdentityRepository(HipRecordStore store) : IHipIdentityRepository
{
    private const string Partition = "identity";

    public Task<HipIdentity> SaveAsync(HipIdentity identity, CancellationToken cancellationToken) =>
        Save(identity, cancellationToken);

    public Task<HipIdentity?> GetAsync(string identityId, CancellationToken cancellationToken) =>
        store.GetAsync<HipIdentity>(Partition, identityId, cancellationToken);

    private async Task<HipIdentity> Save(HipIdentity identity, CancellationToken cancellationToken)
    {
        await store.SaveAsync(Partition, identity.IdentityId, identity, cancellationToken);
        return identity;
    }
}
