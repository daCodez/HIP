namespace HIP.Application.Simulation;

public sealed record RuleSimulationResult(
    string SimulationId,
    string RuleId,
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
    string RecommendedMode,
    string ImpactClassification,
    IReadOnlyCollection<string> MatchedRules,
    IReadOnlyCollection<RuleSimulationCaseResult> FailedCases,
    RuleSimulationRollbackPlan RollbackPlan,
    IReadOnlyCollection<RuleSimulationCaseResult> CaseResults);

public sealed record RuleSimulationRollbackPlan(
    string AffectedRuleId,
    int? PreviousRuleVersion,
    string RollbackReason,
    bool CanRollback,
    DateTimeOffset CreatedAtUtc);
