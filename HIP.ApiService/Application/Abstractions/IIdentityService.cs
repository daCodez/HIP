using HIP.ApiService.Application.Contracts;

namespace HIP.ApiService.Application.Abstractions;

public interface IIdentityService
{
    Task<IdentityDto?> GetByIdAsync(string id, CancellationToken cancellationToken);
}
