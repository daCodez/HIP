namespace HIP.Application.Identity;

/// <summary>
/// Domain verification states returned by direct DNS TXT checks.
/// </summary>
public enum DomainVerificationCheckStatus
{
    /// <summary>
    /// No HIP DNS TXT verification record exists for the domain.
    /// </summary>
    NotConfigured,

    /// <summary>
    /// HIP could not complete the check because DNS is temporarily unavailable or inconclusive.
    /// </summary>
    PendingVerification,

    /// <summary>
    /// The HIP DNS TXT record exists and matches the expected token.
    /// </summary>
    Verified,

    /// <summary>
    /// A HIP DNS TXT record exists, but it does not match the expected token.
    /// </summary>
    Invalid
}

/// <summary>
/// Public-safe response for a DNS TXT verification check.
/// </summary>
/// <param name="Domain">Normalized domain that was checked.</param>
/// <param name="RecordName">DNS record name queried by HIP.</param>
/// <param name="Status">Verification status from the DNS lookup.</param>
/// <param name="CheckedAtUtc">UTC timestamp when HIP completed the check.</param>
/// <param name="Message">Plain-English explanation that does not include the secret token.</param>
public sealed record DomainVerificationCheckResult(
    string Domain,
    string RecordName,
    DomainVerificationCheckStatus Status,
    DateTimeOffset CheckedAtUtc,
    string Message);
