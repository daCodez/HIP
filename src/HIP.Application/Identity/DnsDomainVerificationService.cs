using HIP.Application.PublicLookup;
using HIP.Domain.Identity;
using Microsoft.Extensions.Logging;

namespace HIP.Application.Identity;

/// <summary>
/// Verifies HIP website identity using DNS TXT records at _hip.{domain}.
/// </summary>
public sealed class DnsDomainVerificationService(
    IDnsTxtRecordResolver txtRecordResolver,
    IDomainVerificationRequestRepository verificationRepository,
    ILogger<DnsDomainVerificationService> logger) : IDomainVerificationService
{
    private const string VerificationPrefix = "hip-site-verification=";

    /// <summary>
    /// Creates a domain verification challenge token for DNS TXT or .well-known based verification.
    /// </summary>
    /// <param name="domain">Domain controlled by the website owner.</param>
    /// <param name="method">Verification method requested by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The created verification request.</returns>
    public async Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken)
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

        return await verificationRepository.SaveAsync(request, cancellationToken);
    }

    /// <summary>
    /// Verifies an existing domain challenge. DNS TXT verification queries live DNS; .well-known remains an MVP placeholder.
    /// </summary>
    /// <param name="domain">Domain being verified.</param>
    /// <param name="method">Verification method used for the challenge.</param>
    /// <param name="token">Expected verification token supplied by the owner.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The updated verification request.</returns>
    public async Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken);
        if (request is null)
        {
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        }
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried or reactivated.");
        }

        var status = method switch
        {
            VerificationMethod.DnsTxt => MapDnsCheckStatus((await CheckDnsTxtAsync(normalized, token, cancellationToken)).Status),
            VerificationMethod.WellKnownHipJson => TokensMatch(request.Token, token) ? VerificationStatus.Verified : VerificationStatus.Unverified,
            _ => throw new ArgumentException("MVP verification supports DNS TXT and .well-known/hip.json only.", nameof(method))
        };

        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? DateTimeOffset.UtcNow : null
        };
        return await verificationRepository.SaveAsync(updated, cancellationToken);
    }

    /// <summary>
    /// Retries a persisted DNS challenge using its stored token internally.
    /// </summary>
    public async Task<DomainVerificationRetryResult> RetryAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        if (method != VerificationMethod.DnsTxt)
        {
            throw new InvalidOperationException("Automated retry is available only for production DNS TXT verification.");
        }

        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        if (request.Status == VerificationStatus.Revoked)
        {
            throw new InvalidOperationException("Revoked domain verification cannot be retried.");
        }

        var check = await CheckDnsTxtAsync(normalized, request.Token, cancellationToken);
        var status = MapDnsCheckStatus(check.Status);
        var updated = request with
        {
            Status = status,
            VerifiedAtUtc = status == VerificationStatus.Verified ? DateTimeOffset.UtcNow : null
        };
        await verificationRepository.SaveAsync(updated, cancellationToken);
        return new DomainVerificationRetryResult(updated, check);
    }

    /// <summary>
    /// Revokes a persisted challenge and removes its verified timestamp.
    /// </summary>
    public async Task<DomainVerificationRequest> RevokeAsync(
        string domain,
        VerificationMethod method,
        CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var request = await verificationRepository.GetAsync(normalized, method, cancellationToken) ??
            throw new ArgumentException("Domain verification request was not found.", nameof(domain));
        var revoked = request with { Status = VerificationStatus.Revoked, VerifiedAtUtc = null };
        return await verificationRepository.SaveAsync(revoked, cancellationToken);
    }

    /// <summary>
    /// Checks whether _hip.{domain} contains the expected HIP TXT verification value.
    /// </summary>
    /// <param name="domain">Domain whose _hip TXT record should be checked.</param>
    /// <param name="expectedToken">Expected raw verification token.</param>
    /// <param name="cancellationToken">Token used to cancel the DNS lookup.</param>
    /// <returns>A status result that never echoes the expected token.</returns>
    public async Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken)
    {
        var normalized = DomainInputValidator.ValidateAndNormalize(domain);
        var token = NormalizeExpectedToken(expectedToken);
        var recordName = $"_hip.{normalized}";
        var checkedAtUtc = DateTimeOffset.UtcNow;

        try
        {
            var records = await txtRecordResolver.ResolveTxtRecordsAsync(recordName, cancellationToken);
            var status = DetermineStatus(records, token);
            logger.LogInformation("HIP DNS verification checked {Domain} with status {Status}.", normalized, status);
            return new DomainVerificationCheckResult(normalized, recordName, status, checkedAtUtc, MessageFor(status));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "HIP DNS verification could not complete for {Domain}; token was not logged.", normalized);
            return new DomainVerificationCheckResult(
                normalized,
                recordName,
                DomainVerificationCheckStatus.PendingVerification,
                checkedAtUtc,
                "HIP could not complete the DNS check yet. Try again after DNS is available.");
        }
    }

    /// <summary>
    /// Converts a user-supplied token into the raw token value HIP expects inside the TXT record.
    /// </summary>
    /// <param name="expectedToken">Token supplied to the API or verification flow.</param>
    /// <returns>Raw token without the TXT prefix.</returns>
    private static string NormalizeExpectedToken(string expectedToken)
    {
        if (string.IsNullOrWhiteSpace(expectedToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        var trimmed = expectedToken.Trim();
        if (trimmed.Length > 256 || trimmed.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("Expected verification token must be 1-256 non-whitespace characters.", nameof(expectedToken));
        }

        var rawToken = trimmed.StartsWith(VerificationPrefix, StringComparison.OrdinalIgnoreCase)
            ? trimmed[VerificationPrefix.Length..]
            : trimmed;

        if (string.IsNullOrWhiteSpace(rawToken))
        {
            throw new ArgumentException("Expected verification token is required.", nameof(expectedToken));
        }

        return rawToken;
    }

    /// <summary>
    /// Maps the DNS-specific check result onto the existing identity verification lifecycle.
    /// </summary>
    /// <param name="status">DNS TXT verification status.</param>
    /// <returns>Stored identity verification status.</returns>
    private static VerificationStatus MapDnsCheckStatus(DomainVerificationCheckStatus status) => status switch
    {
        DomainVerificationCheckStatus.Verified => VerificationStatus.Verified,
        DomainVerificationCheckStatus.Invalid => VerificationStatus.Unverified,
        _ => VerificationStatus.Pending
    };

    /// <summary>
    /// Determines the verification status from DNS TXT values without leaking expected token contents.
    /// </summary>
    /// <param name="records">TXT values returned by DNS.</param>
    /// <param name="expectedToken">Normalized raw expected token.</param>
    /// <returns>Verification status for the DNS evidence.</returns>
    private static DomainVerificationCheckStatus DetermineStatus(IReadOnlyCollection<string> records, string expectedToken)
    {
        if (records.Count == 0)
        {
            return DomainVerificationCheckStatus.NotConfigured;
        }

        var hipRecords = records
            .Select(NormalizeTxtValue)
            .Where(value => value.StartsWith(VerificationPrefix, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (hipRecords.Length == 0)
        {
            return DomainVerificationCheckStatus.NotConfigured;
        }

        return hipRecords.Any(value => TokensMatch(value[VerificationPrefix.Length..], expectedToken))
            ? DomainVerificationCheckStatus.Verified
            : DomainVerificationCheckStatus.Invalid;
    }

    /// <summary>
    /// Normalizes TXT records returned by different DNS clients by trimming quotes and whitespace.
    /// </summary>
    /// <param name="value">TXT value returned by the resolver.</param>
    /// <returns>Comparable TXT value.</returns>
    private static string NormalizeTxtValue(string value) => value.Trim().Trim('"');

    /// <summary>
    /// Compares tokens using ordinal comparison because DNS verification tokens are opaque identifiers.
    /// </summary>
    /// <param name="left">First token.</param>
    /// <param name="right">Second token.</param>
    /// <returns>True when the tokens match exactly.</returns>
    private static bool TokensMatch(string left, string right) => string.Equals(left, right, StringComparison.Ordinal);

    /// <summary>
    /// Builds a plain-English status message that avoids exposing verification tokens.
    /// </summary>
    /// <param name="status">Verification status.</param>
    /// <returns>Human-readable explanation.</returns>
    private static string MessageFor(DomainVerificationCheckStatus status) => status switch
    {
        DomainVerificationCheckStatus.Verified => "HIP found the expected DNS TXT record for this domain.",
        DomainVerificationCheckStatus.Invalid => "HIP found a DNS TXT verification record, but it did not match the expected token.",
        DomainVerificationCheckStatus.PendingVerification => "HIP could not complete the DNS verification check yet.",
        _ => "HIP did not find a DNS TXT verification record for this domain."
    };
}
