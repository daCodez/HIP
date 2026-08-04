using System.Text.Json.Serialization;

namespace HIP.Application.Dns;

/// <summary>DNS record types supported by the first bounded HIP DNS provider milestone.</summary>
public enum DnsLookupRecordType
{
    /// <summary>IPv4 address record.</summary>
    A = 1,

    /// <summary>IPv6 address record.</summary>
    Aaaa = 28
}

/// <summary>A public DNS answer returned by a replaceable lookup provider.</summary>
/// <param name="Name">Canonical DNS owner name.</param>
/// <param name="Type">DNS record type.</param>
/// <param name="TtlSeconds">Provider-supplied time to live in seconds.</param>
/// <param name="Data">Public DNS record value.</param>
public sealed record DnsLookupAnswer(
    string Name,
    DnsLookupRecordType Type,
    int TtlSeconds,
    string Data);

/// <summary>Provider-neutral DNS lookup result.</summary>
/// <param name="Status">DNS response code, where zero is NoError and three is NXDOMAIN.</param>
/// <param name="IsTruncated">Whether the upstream response was truncated.</param>
/// <param name="IsRecursionAvailable">Whether the upstream provider supports recursion.</param>
/// <param name="Answers">Public DNS answers.</param>
public sealed record DnsProviderLookupResult(
    int Status,
    bool IsTruncated,
    bool IsRecursionAvailable,
    IReadOnlyCollection<DnsLookupAnswer> Answers);

/// <summary>
/// Resolves public DNS records without coupling HIP application logic to a specific recursive resolver.
/// </summary>
public interface IDnsLookupProvider
{
    /// <summary>Stable provider name safe for diagnostics and API responses.</summary>
    string Name { get; }

    /// <summary>Resolves a bounded public DNS query.</summary>
    Task<DnsProviderLookupResult> LookupAsync(
        string domain,
        DnsLookupRecordType recordType,
        CancellationToken cancellationToken);
}

/// <summary>DNS-JSON question entry.</summary>
public sealed record DnsJsonQuestion(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] int Type);

/// <summary>DNS-JSON answer entry.</summary>
public sealed record DnsJsonAnswer(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] int Type,
    [property: JsonPropertyName("TTL")] int TtlSeconds,
    [property: JsonPropertyName("data")] string Data);

/// <summary>
/// Public-safe HIP trust extension carried alongside DNS answers. It is evidence, not an authoritative DNS assertion.
/// </summary>
public sealed record HipDnsTrustSummary(
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("displayScore")] int? DisplayScore,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("riskLevel")] string RiskLevel,
    [property: JsonPropertyName("verificationStatus")] string VerificationStatus,
    [property: JsonPropertyName("evidenceCoverage")] string EvidenceCoverage,
    [property: JsonPropertyName("evidenceConfidence")] string EvidenceConfidence,
    [property: JsonPropertyName("recommendedAction")] string RecommendedAction,
    [property: JsonPropertyName("lastCheckedUtc")] DateTimeOffset LastCheckedUtc,
    [property: JsonPropertyName("publicLookupUrl")] string PublicLookupUrl,
    [property: JsonPropertyName("dataSource")] string DataSource,
    [property: JsonPropertyName("isAuthoritative")] bool IsAuthoritative);

/// <summary>DNS-JSON response enriched with a public-safe HIP trust summary.</summary>
public sealed record HipAwareDnsLookupResponse(
    [property: JsonPropertyName("Status")] int Status,
    [property: JsonPropertyName("TC")] bool IsTruncated,
    [property: JsonPropertyName("RD")] bool IsRecursionDesired,
    [property: JsonPropertyName("RA")] bool IsRecursionAvailable,
    [property: JsonPropertyName("AD")] bool IsAuthenticData,
    [property: JsonPropertyName("CD")] bool IsCheckingDisabled,
    [property: JsonPropertyName("Question")] IReadOnlyCollection<DnsJsonQuestion> Question,
    [property: JsonPropertyName("Answer")] IReadOnlyCollection<DnsJsonAnswer> Answer,
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("hip")] HipDnsTrustSummary Hip);

/// <summary>Combines public DNS answers with HIP public trust evidence.</summary>
public interface IHipAwareDnsLookupService
{
    /// <summary>Resolves a normalized domain and attaches its public-safe HIP summary.</summary>
    Task<HipAwareDnsLookupResponse> LookupAsync(
        string domain,
        DnsLookupRecordType recordType,
        CancellationToken cancellationToken);
}
