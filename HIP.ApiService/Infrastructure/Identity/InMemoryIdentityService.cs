using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Identity;

public sealed class InMemoryIdentityService(ILogger<InMemoryIdentityService> logger) : IIdentityService
{
    private static readonly Dictionary<string, IdentityModel> Identities = new(StringComparer.Ordinal)
    {
        ["hip-system"] = new("hip-system", "pkref:placeholder")
    };

    public Task<IdentityModel?> GetByIdAsync(string id, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id); // validation
        logger.LogDebug("Identity lookup requested for {IdentityId}", id); // logging/security awareness: no secrets

        Identities.TryGetValue(id, out var value);
        return Task.FromResult(value); // performance awareness: O(1) in-memory lookup
    }
}
