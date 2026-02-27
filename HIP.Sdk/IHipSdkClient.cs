using HIP.Sdk.Models;

namespace HIP.Sdk;

public interface IHipSdkClient
{
    Task<StatusResponse> GetStatusAsync(CancellationToken cancellationToken = default);
    Task<IdentityDto?> GetIdentityAsync(string id, CancellationToken cancellationToken = default);
    Task<ReputationDto?> GetReputationAsync(string identityId, CancellationToken cancellationToken = default);
}
