using HIP.Domain.Risk;

namespace HIP.Domain.Safety;

public sealed record SafetyResult(
    string OriginalUrl,
    string? FinalDestinationUrl,
    RiskStatus RiskLevel,
    string Reason,
    int DomainScore,
    int? SenderScore,
    string RecommendedAction,
    bool AllowContinue,
    bool ShouldRouteToSafetyPage,
    bool CanReportAsSafe,
    bool CanReportAsDangerous);

public sealed record PrivacySafeRiskReport(
    string RiskyUrl,
    string Domain,
    string UrlHash,
    string? SenderHash,
    string Platform,
    string RiskReason,
    DateTimeOffset Timestamp,
    string HipSignaturePlaceholder);
