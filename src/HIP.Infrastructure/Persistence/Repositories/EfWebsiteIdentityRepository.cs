using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// Persists registered website identities in the encrypted HIP record store.
/// </summary>
public sealed class EfWebsiteIdentityRepository(HipRecordStore store) : IWebsiteIdentityRepository
{
    private const string Partition = "website-identity";

    /// <summary>
    /// Saves a website identity and normalizes the domain used as the lookup key.
    /// </summary>
    /// <param name="websiteIdentity">Website identity to save.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The saved website identity.</returns>
    public async Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(websiteIdentity.Domain);
        var safeIdentity = websiteIdentity with { Domain = normalized };
        await store.SaveAsync(Partition, normalized, safeIdentity, cancellationToken);
        return safeIdentity;
    }

    /// <summary>
    /// Gets a website identity by domain.
    /// </summary>
    /// <param name="domain">Domain to look up.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored website identity, or null when it has not been registered.</returns>
    public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        return store.GetAsync<WebsiteIdentity>(Partition, normalized, cancellationToken);
    }

    /// <summary>
    /// Lists all persisted website identities without exposing verification challenge tokens.
    /// </summary>
    public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<WebsiteIdentity>(Partition, cancellationToken);
}
