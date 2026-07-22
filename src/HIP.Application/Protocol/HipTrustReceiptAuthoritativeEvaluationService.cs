using FluentValidation;
using HIP.Application.SiteSafety;

namespace HIP.Application.Protocol;

/// <summary>
/// Produces the server-authoritative Site Safety evaluation used to issue a signed trust receipt.
/// </summary>
/// <remarks>
/// Receipt issuance intentionally accepts only the caller's validated target URL. Client-observed signals and
/// client version metadata remain useful for ordinary Site Safety scans, but they are not authoritative enough to
/// influence a server-signed protocol artifact.
/// </remarks>
public interface IHipTrustReceiptAuthoritativeEvaluationService
{
    /// <summary>
    /// Validates the untrusted target URL and evaluates a new request containing no client-authored signals.
    /// </summary>
    /// <param name="untrustedRequest">Untrusted public receipt-issuance request.</param>
    /// <param name="cancellationToken">Token used to cancel validation or scan work.</param>
    /// <returns>The server-authoritative Site Safety evaluation supplied to receipt issuance.</returns>
    Task<SiteSafetyScanResult> EvaluateAsync(
        HipTrustReceiptIssueRequest untrustedRequest,
        CancellationToken cancellationToken);
}

/// <summary>
/// Validates a receipt target and strips all client-authored evidence before invoking Site Safety.
/// </summary>
public sealed class HipTrustReceiptAuthoritativeEvaluationService(
    IValidator<SiteSafetyScanRequest> validator,
    ISiteSafetyScanner scanner) : IHipTrustReceiptAuthoritativeEvaluationService
{
    /// <inheritdoc />
    public async Task<SiteSafetyScanResult> EvaluateAsync(
        HipTrustReceiptIssueRequest untrustedRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(untrustedRequest);

        var authoritativeRequest = new SiteSafetyScanRequest(untrustedRequest.Url);
        await validator.ValidateAndThrowAsync(authoritativeRequest, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        return await scanner.ScanAsync(authoritativeRequest, cancellationToken);
    }
}
