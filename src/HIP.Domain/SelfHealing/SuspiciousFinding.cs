using HIP.Domain.Risk;

namespace HIP.Domain.SelfHealing;

public sealed record SuspiciousFinding(
    string FindingId,
    FindingType FindingType,
    string Domain,
    string UrlHash,
    string Platform,
    RiskStatus RiskLevel,
    string Reason,
    DateTimeOffset DetectedAtUtc,
    FindingSourceType SourceType,
    ReporterTrustLevel ReporterTrustLevel,
    IReadOnlyDictionary<string, string> PrivacySafeEvidence);
