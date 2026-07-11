using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Domain.Reporting;

public sealed record RiskFindingReport(
    string ReportId,
    SourceClient SourceClient,
    ReportPlatform Platform,
    TargetType TargetType,
    string Domain,
    string? UrlHash,
    string? OriginalUrl,
    string? SenderHash,
    RiskStatus RiskLevel,
    string Reason,
    DateTimeOffset DetectedAtUtc,
    ReporterTrustLevel ReporterTrustLevel,
    PrivacySafeEvidence PrivacySafeEvidence,
    string HipSignature,
    string? ConsumerScopeHash = null);
