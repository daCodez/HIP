using HIP.Domain.Risk;

namespace HIP.Domain.Safety;

public enum SafetyContinuationRequirement
{
    None = 0,
    Confirmation,
    ExtraConfirmation,
    Blocked
}

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
    bool CanReportAsDangerous,
    int PageTrustScore = 0,
    int ContentRiskScore = 0,
    int FinalHipScore = 0,
    SafetyContinuationRequirement ContinuationRequirement = SafetyContinuationRequirement.None)
{
    public bool ContentRiskScoreHigherMeansMoreRisk => true;
}

public sealed record PrivacySafeRiskReport(
    string RiskyUrl,
    string Domain,
    string UrlHash,
    string? SenderHash,
    string Platform,
    string RiskReason,
    DateTimeOffset Timestamp,
    string HipSignaturePlaceholder);
