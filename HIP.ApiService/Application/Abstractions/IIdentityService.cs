namespace HIP.ApiService.Application.Abstractions;

public interface IIdentityService
{
    Task<IdentityModel?> GetByIdAsync(string id, CancellationToken cancellationToken);
}

public sealed record IdentityModel(string Id, string PublicKeyRef);
