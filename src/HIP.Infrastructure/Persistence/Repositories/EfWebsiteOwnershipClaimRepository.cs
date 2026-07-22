using HIP.Application.Identity;
using HIP.Application.PublicLookup;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Stores create-only, encrypted website ownership claims.</summary>
public sealed class EfWebsiteOwnershipClaimRepository(HipRecordStore store) : IWebsiteOwnershipClaimRepository
{
    private const string Partition = "website-owner-claim";

    public Task<bool> TryCreateAsync(WebsiteOwnershipClaim claim, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        var normalized = DomainInputValidator.ValidateAndNormalize(claim.Domain);
        if (claim.Version != 1 || claim.ClaimedAtUtc == default ||
            claim.OwnerScopeHash is not { Length: 71 } || !claim.OwnerScopeHash.StartsWith("sha256:", StringComparison.Ordinal))
        {
            throw new ArgumentException("Website ownership claim metadata is invalid.", nameof(claim));
        }

        return store.TrySaveVersionedAsync(
            Partition,
            normalized,
            claim with { Domain = normalized },
            expectedVersion: 0,
            newVersion: 1,
            cancellationToken);
    }

    public Task<WebsiteOwnershipClaim?> GetAsync(string domain, CancellationToken cancellationToken) =>
        store.GetAsync<WebsiteOwnershipClaim>(
            Partition,
            DomainInputValidator.ValidateAndNormalize(domain),
            cancellationToken);
}
