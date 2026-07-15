using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Stores signed website identity records in durable persistence instead of process-local memory.
/// </summary>
public interface IWebsiteIdentityRepository
{
    /// <summary>
    /// Saves the current website identity record, including verification status.
    /// </summary>
    /// <param name="websiteIdentity">Website identity to persist.</param>
    /// <param name="cancellationToken">Token used to cancel database work.</param>
    /// <returns>The persisted website identity.</returns>
    Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a registered website identity by domain.
    /// </summary>
    /// <param name="domain">Normalized domain name.</param>
    /// <param name="cancellationToken">Token used to cancel database work.</param>
    /// <returns>The website identity, or null when the domain has not been registered.</returns>
    Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken);

    /// <summary>
    /// Lists all registered website identities for administrative verification operations.
    /// </summary>
    Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken);
}
