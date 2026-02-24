namespace HIP.ApiService.Application.Abstractions;

public interface IHipEnvelopeVerifier
{
    Task<HipEnvelopeVerificationResult> VerifyIfRequiredAsync(HttpContext httpContext, CancellationToken cancellationToken);
}

public sealed record HipEnvelopeVerificationResult(bool IsValid, int StatusCode, string Code, string Reason);
