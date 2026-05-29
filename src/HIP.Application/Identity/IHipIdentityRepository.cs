using HIP.Domain.Identity;

namespace HIP.Application.Identity;

public interface IHipIdentityRepository
{
    Task<HipIdentity> SaveAsync(HipIdentity identity, CancellationToken cancellationToken);

    Task<HipIdentity?> GetAsync(string identityId, CancellationToken cancellationToken);
}
