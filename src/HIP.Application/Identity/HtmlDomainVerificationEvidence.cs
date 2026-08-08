using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>Retrieves bounded HTML-file or meta-tag evidence for a domain challenge.</summary>
public interface IHtmlDomainVerificationEvidenceProvider
{
    /// <summary>Checks a fixed HTTPS location for the active challenge without returning page content.</summary>
    Task<DomainVerificationCheckResult> CheckAsync(
        string domain,
        VerificationMethod method,
        string expectedToken,
        CancellationToken cancellationToken);
}

/// <summary>Fail-closed provider used when safe remote HTML retrieval is not configured.</summary>
public sealed class UnavailableHtmlDomainVerificationEvidenceProvider : IHtmlDomainVerificationEvidenceProvider
{
    /// <inheritdoc />
    public Task<DomainVerificationCheckResult> CheckAsync(
        string domain,
        VerificationMethod method,
        string expectedToken,
        CancellationToken cancellationToken)
    {
        _ = expectedToken;
        cancellationToken.ThrowIfCancellationRequested();
        var location = method == VerificationMethod.HtmlFile
            ? $"https://{domain}/hip-verification.txt"
            : $"https://{domain}/";
        return Task.FromResult(new DomainVerificationCheckResult(
            domain,
            location,
            DomainVerificationCheckStatus.PendingVerification,
            DateTimeOffset.UtcNow,
            "Secure HTML verification retrieval is unavailable in this runtime."));
    }
}
