using HIP.Domain.Risk;

namespace HIP.Domain.Reputation;

public sealed record ReputationProfile(
    string ProfileId,
    ReputationSubjectType TargetType,
    string TargetId,
    int CurrentScore,
    RiskStatus Status,
    int EventCount,
    int ConfirmedAbuseCount,
    int AccidentalIssueCount,
    DateTimeOffset LastUpdatedUtc,
    IReadOnlyCollection<string> Explanations);
