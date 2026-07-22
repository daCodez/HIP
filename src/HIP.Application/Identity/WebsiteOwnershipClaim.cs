using System.Collections.Concurrent;

namespace HIP.Application.Identity;

/// <summary>
/// Privacy-safe ownership binding for a normalized website domain.
/// Raw actor identifiers are never stored in this record.
/// </summary>
public sealed record WebsiteOwnershipClaim(
    string Domain,
    string OwnerScopeHash,
    string ClaimedByRole,
    DateTimeOffset ClaimedAtUtc,
    long Version = 1);

public interface IWebsiteOwnershipClaimRepository
{
    Task<bool> TryCreateAsync(WebsiteOwnershipClaim claim, CancellationToken cancellationToken);
    Task<WebsiteOwnershipClaim?> GetAsync(string domain, CancellationToken cancellationToken);
}

public sealed class InMemoryWebsiteOwnershipClaimRepository : IWebsiteOwnershipClaimRepository
{
    private readonly ConcurrentDictionary<string, WebsiteOwnershipClaim> claims = new(StringComparer.OrdinalIgnoreCase);

    public Task<bool> TryCreateAsync(WebsiteOwnershipClaim claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(claims.TryAdd(claim.Domain, claim));
    }

    public Task<WebsiteOwnershipClaim?> GetAsync(string domain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        claims.TryGetValue(domain, out var claim);
        return Task.FromResult(claim);
    }
}
