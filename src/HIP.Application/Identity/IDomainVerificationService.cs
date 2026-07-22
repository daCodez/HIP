using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// Coordinates website/domain verification challenges without treating successful verification as a safety signal.
/// </summary>
public interface IDomainVerificationService
{
    /// <summary>
    /// Creates a verification challenge for a domain and method.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method requested by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The created verification request.</returns>
    Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the existing challenge or atomically creates one without replacing its token.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method whose challenge must remain stable.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The existing or newly elected challenge.</returns>
    Task<DomainVerificationRequest> GetOrStartAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken);

    /// <summary>Gets an existing challenge without creating or rotating one.</summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method associated with the challenge.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored challenge, or null when one has not been created.</returns>
    Task<DomainVerificationRequest?> GetAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies a previously created domain challenge.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token supplied by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken);

    /// <summary>
    /// Retries a stored DNS challenge without accepting or returning raw token input.
    /// </summary>
    Task<DomainVerificationRetryResult> RetryAsync(string domain, VerificationMethod method, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes the stored challenge so later retries cannot reactivate it.
    /// </summary>
    Task<DomainVerificationRequest> RevokeAsync(string domain, VerificationMethod method, CancellationToken cancellationToken);

    /// <summary>Replaces an expired challenge with a new bounded token generation.</summary>
    Task<DomainVerificationRequest> RenewExpiredAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This domain verification provider does not support expired challenge renewal.");

    /// <summary>
    /// Checks the live DNS TXT verification status for a domain.
    /// </summary>
    /// <param name="domain">Domain whose _hip TXT record should be checked.</param>
    /// <param name="expectedToken">Expected raw verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the DNS lookup.</param>
    /// <returns>A privacy-safe DNS verification result.</returns>
    Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken);
}
