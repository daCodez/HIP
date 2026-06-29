using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Stores HIP domain verification challenges in durable persistence so ownership checks survive app restarts.
/// </summary>
public interface IDomainVerificationRequestRepository
{
    /// <summary>
    /// Saves the latest state of a domain verification challenge without exposing the token to logs.
    /// </summary>
    /// <param name="request">Verification challenge to persist.</param>
    /// <param name="cancellationToken">Token used to cancel database work.</param>
    /// <returns>The persisted verification challenge.</returns>
    Task<DomainVerificationRequest> SaveAsync(DomainVerificationRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the current verification challenge for a domain and method.
    /// </summary>
    /// <param name="domain">Normalized domain name.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="cancellationToken">Token used to cancel database work.</param>
    /// <returns>The stored challenge, or null when the domain has not started verification.</returns>
    Task<DomainVerificationRequest?> GetAsync(string domain, VerificationMethod method, CancellationToken cancellationToken);
}
