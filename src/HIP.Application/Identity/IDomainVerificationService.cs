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
    /// Verifies a previously created domain challenge.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token supplied by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken);

    /// <summary>
    /// Checks the live DNS TXT verification status for a domain.
    /// </summary>
    /// <param name="domain">Domain whose _hip TXT record should be checked.</param>
    /// <param name="expectedToken">Expected raw verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the DNS lookup.</param>
    /// <returns>A privacy-safe DNS verification result.</returns>
    Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken);
}
