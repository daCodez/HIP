using HIP.Domain.Risk;

namespace HIP.Domain.SelfHealing;

public sealed record PatternCluster(
    string ClusterId,
    FindingType PatternType,
    IReadOnlyCollection<SuspiciousFinding> Findings,
    string Summary,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    int FindingCount,
    RiskStatus AverageRiskLevel,
    decimal ConfidenceHint);
