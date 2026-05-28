namespace HIP.Application.Simulation;

public sealed record RuleSimulationResult(
    bool Passed,
    int TotalTestCases,
    int PassedCount,
    int FailedCount,
    decimal DetectionRate,
    decimal FalsePositiveRisk,
    decimal FalseNegativeRisk,
    string SpeedImpact,
    string PrivacyImpact,
    decimal ConfidenceScore,
    string RecommendedAction,
    IReadOnlyCollection<RuleSimulationCaseResult> CaseResults);
