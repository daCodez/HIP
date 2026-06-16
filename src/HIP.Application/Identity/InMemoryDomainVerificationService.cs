using System.Collections.Concurrent;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Application.Identity;

/// <summary>
/// In-memory verification helper used by focused tests and isolated local flows that do not need live DNS.
/// </summary>
public sealed class InMemoryDomainVerificationService : IDomainVerificationService
{
    private readonly ConcurrentDictionary<string, DomainVerificationRequest> _requests = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Creates an in-memory verification challenge.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method requested by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The created verification request.</returns>
    public Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
    {
        if (method is not (VerificationMethod.DnsTxt or VerificationMethod.WellKnownHipJson))
        {
            throw new ArgumentException("MVP verification supports DNS TXT and .well-known/hip.json only.", nameof(method));
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = new DomainVerificationRequest(
            normalized,
            method,
            Guid.NewGuid().ToString("N"),
            VerificationStatus.Pending,
            DateTimeOffset.UtcNow,
            null);
        _requests[Key(normalized, method)] = request;
        return Task.FromResult(request);
    }

    /// <summary>
    /// Verifies an in-memory challenge by exact token match.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    public Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        if (!_requests.TryGetValue(Key(normalized, method), out var request))
        {
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        }

        var status = string.Equals(request.Token, token, StringComparison.Ordinal)
            ? VerificationStatus.Verified
            : VerificationStatus.Unverified;
        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? DateTimeOffset.UtcNow : null
        };
        _requests[Key(normalized, method)] = updated;
        return Task.FromResult(updated);
    }

    /// <summary>
    /// Performs a deterministic in-memory DNS-style check for tests without doing network I/O.
    /// </summary>
    /// <param name="domain">Domain whose record would be checked.</param>
    /// <param name="expectedToken">Expected verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>A verified result only when an in-memory DNS challenge exists for the exact token.</returns>
    public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        if (string.IsNullOrWhiteSpace(expectedToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        var status = _requests.TryGetValue(Key(normalized, VerificationMethod.DnsTxt), out var request)
            ? string.Equals(request.Token, expectedToken, StringComparison.Ordinal)
                ? DomainVerificationCheckStatus.Verified
                : DomainVerificationCheckStatus.Invalid
            : DomainVerificationCheckStatus.NotConfigured;

        return Task.FromResult(new DomainVerificationCheckResult(
            normalized,
            $"_hip.{normalized}",
            status,
            DateTimeOffset.UtcNow,
            status == DomainVerificationCheckStatus.Verified
                ? "HIP found the expected DNS TXT record for this domain."
                : "HIP did not verify this domain in the in-memory test store."));
    }

    /// <summary>
    /// Creates a stable lookup key for in-memory verification requests.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="method">Verification method.</param>
    /// <returns>Dictionary key.</returns>
    private static string Key(string domain, VerificationMethod method) => $"{method}:{domain}";
}
