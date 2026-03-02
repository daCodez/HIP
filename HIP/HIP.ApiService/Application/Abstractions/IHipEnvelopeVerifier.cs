namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Verifies HIP signed-envelope headers/body for requests that require envelope auth.
/// </summary>
public interface IHipEnvelopeVerifier
{
    /// <summary>
    /// Verifies the current request when envelope verification is required by policy.
    /// </summary>
    /// <param name="httpContext">Current HTTP context containing headers/body metadata.</param>
    /// <param name="cancellationToken">Cancellation token for verification operations.</param>
    /// <returns>
    /// Verification result with allow/deny status and an API-facing error contract.
    /// </returns>
    Task<HipEnvelopeVerificationResult> VerifyIfRequiredAsync(HttpContext httpContext, CancellationToken cancellationToken);
}

/// <summary>
/// Represents the outcome of HIP envelope verification.
/// </summary>
/// <param name="IsValid">Indicates whether the request passed verification.</param>
/// <param name="StatusCode">HTTP status code to return when verification fails.</param>
/// <param name="Code">Stable machine-readable failure code.</param>
/// <param name="Reason">Human-readable failure reason.</param>
public sealed record HipEnvelopeVerificationResult(bool IsValid, int StatusCode, string Code, string Reason);
