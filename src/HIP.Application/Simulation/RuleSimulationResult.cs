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
    IReadOnlyCollection<RuleSimulationCaseResult> CaseResults,
    int RuleVersion = 1,
    string FixtureSetId = "legacy-fixtures",
    DateTimeOffset StartedAtUtc = default,
    DateTimeOffset CompletedAtUtc = default,
    long Version = 1)
{
    /// <summary>
    /// SHA-256 fingerprint of the exact rule snapshot that produced this result.
    /// Legacy records may omit it, but they cannot authorize a new approval workflow.
    /// </summary>
    public string? RuleDefinitionHash { get; init; }
}

public sealed record RuleSimulationRollbackPlan(
    string AffectedRuleId,
    int? PreviousRuleVersion,
    string RollbackReason,
    bool CanRollback,
    DateTimeOffset CreatedAtUtc);
