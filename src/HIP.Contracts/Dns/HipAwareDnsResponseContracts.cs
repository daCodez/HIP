using System.Text.Json.Serialization;

namespace HIP.Application.Dns;

/// <summary>Describes one DNS-JSON question.</summary>
/// <param name="Name">Public DNS name.</param>
/// <param name="Type">Numeric DNS record type.</param>
public sealed record DnsJsonQuestion(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] int Type);

/// <summary>Describes one public DNS-JSON answer.</summary>
/// <param name="Name">Public DNS owner name.</param>
/// <param name="Type">Numeric DNS record type.</param>
/// <param name="TtlSeconds">Public time-to-live value in seconds.</param>
/// <param name="Data">Public record data.</param>
public sealed record DnsJsonAnswer(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] int Type,
    [property: JsonPropertyName("TTL")] int TtlSeconds,
    [property: JsonPropertyName("data")] string Data);

/// <summary>Reports public resolver-derived DNSSEC validation separately from HIP trust evidence.</summary>
/// <param name="Status">Public DNSSEC status label.</param>
/// <param name="IsValidated">Whether the resolver reported authenticated DNS data.</param>
/// <param name="Source">Public evidence source label.</param>
public sealed record DnssecValidationSummary(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("isValidated")] bool IsValidated,
    [property: JsonPropertyName("source")] string Source);

/// <summary>
/// Carries a public-safe HIP trust summary alongside DNS answers. It is evidence, not an authoritative DNS assertion.
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

/// <summary>Combines DNS-JSON fields with resolver evidence and a public-safe HIP trust summary.</summary>
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
    [property: JsonPropertyName("dnssec")] DnssecValidationSummary Dnssec,
    [property: JsonPropertyName("hip")] HipDnsTrustSummary Hip);
