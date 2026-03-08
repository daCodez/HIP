using System.Text.Json;

namespace HIP.Simulator.Core.Models;

public sealed record SecurityEvent(
    string EventType,
    string ActorId,
    string? TargetId,
    DateTimeOffset TimestampUtc,
    JsonElement Payload);

public enum SimulationExecutionMode
{
    Application,
    Protocol,
    Hybrid
}

public enum ProtocolStepType
{
    SignEnvelope,
    VerifyEnvelope,
    ReplayAttempt,
    TimestampSkew,
    IssueReceipt,
    VerifyReceipt,
    ChallengeCreate,
    ChallengeVerify,
    KeyRevoked,
    KeyReplaced
}

public sealed record Scenario(
    string Id,
    string Name,
    string Description,
    string Category,
    IReadOnlyList<string> Tags,
    IReadOnlyList<ScenarioStep> Steps,
    IReadOnlyList<ProtocolScenarioStep> ProtocolSteps,
    ExpectedOutcome ExpectedOutcome,
    bool ShouldBeCovered,
    bool ShouldBeValid,
    SimulationExecutionMode ExecutionMode = SimulationExecutionMode.Application);

public sealed record ScenarioStep(
    int OffsetSeconds,
    string EventType,
    string ActorId,
    string? TargetId,
    JsonElement Payload);

public sealed record ProtocolScenarioStep(
    ProtocolStepType StepType,
    bool ExpectSuccess = true,
    string? Notes = null);

public sealed record ExpectedOutcome(
    IReadOnlyList<string> ExpectedRules,
    string ExpectedAction,
    string ExpectedSeverity);

public sealed record RuleTraceEntry(
    string RuleName,
    bool Matched,
    string Action,
    string Severity,
    string Reason);

public sealed record ScenarioResult(
    string ScenarioId,
    bool Passed,
    bool IsCovered,
    bool IsValid,
    string FinalAction,
    string FinalSeverity,
    IReadOnlyList<string> MatchedRules,
    IReadOnlyList<string> ValidationIssues,
    IReadOnlyList<RuleTraceEntry> RuleTrace,
    IReadOnlyList<string> SideEffects,
    SimulationExecutionMode ExecutionMode,
    PolicySuggestion? Suggestion);

public sealed record EventCoverageSummary(string EventType, int Total, int Covered, int Uncovered, int Invalid);
public sealed record RuleCoverageSummary(string RuleName, int MatchedCount, int EvaluatedCount);
public sealed record FieldCoverageSummary(string FieldName, int PresenceCount, int InvalidCount);

public sealed record CoverageReport(
    IReadOnlyList<EventCoverageSummary> EventCoverage,
    IReadOnlyList<RuleCoverageSummary> RuleCoverage,
    IReadOnlyList<FieldCoverageSummary> FieldCoverage,
    IReadOnlyList<string> UncoveredPatterns,
    IReadOnlyList<string> InvalidPatterns,
    int SuggestedPoliciesCount);

public sealed record PolicySuggestion(
    string RuleName,
    string Category,
    string ConditionExpression,
    string RecommendedAction,
    string RecommendedSeverity,
    string Reason,
    IReadOnlyList<string> NeededSignals,
    string PositiveTestCase,
    string NegativeTestCase,
    string Notes)
{
    public string ToTemplate() => $"""
- Rule: {RuleName}
- Category: {Category}
- When: {ConditionExpression}
- Then: {RecommendedAction}
- Severity: {RecommendedSeverity}
- Notes: {Notes}
- Signals needed: {string.Join(", ", NeededSignals)}
- Tests:
 - Pass: {PositiveTestCase}
 - Fail: {NegativeTestCase}
""";
}

public sealed record SimulationProgressUpdate(
    string Stage,
    int ProcessedScenarios,
    int TotalScenarios,
    string? ScenarioId,
    string Message);

public sealed class SimulationRunOptions
{
    public string InputFolder { get; init; } = "scenarios";
    public string ReportFolder { get; init; } = "out";
    public string? Suite { get; init; }
    public string? ScenarioId { get; init; }
    public int? RandomSeed { get; init; }
    public SimulationExecutionMode? ExecutionModeOverride { get; init; }
    public IProgress<SimulationProgressUpdate>? Progress { get; init; }
    public IReadOnlyList<string> ActionPrecedence { get; init; } =
    [
        "Kill", "Lock", "Block", "Quarantine", "Challenge", "RateLimit", "Warn", "Alert", "LogOnly"
    ];
}

public sealed record SimulationRunResult(
    int TotalScenarios,
    int Passed,
    int Failed,
    int Uncovered,
    int Invalid,
    int SuggestedPoliciesGenerated,
    IReadOnlyList<ScenarioResult> Scenarios,
    CoverageReport Coverage);

public sealed record ThreatCatalogItem(
    string ThreatId,
    string Title,
    string Family,
    string Severity,
    IReadOnlyList<string> ScenarioIds,
    string? MitreTechnique = null,
    string? Notes = null);

public sealed record ThreatCoverageListItem(
    ThreatCatalogItem Threat,
    bool IsInScope);

public sealed record ThreatCoverageSummary(
    int TotalThreats,
    int CoveredThreats,
    int PartialThreats,
    int UncoveredThreats,
    int CriticalUncovered,
    int InScopeThreats,
    int OutOfScopeThreats,
    int CoveredInScopeThreats,
    int PartialInScopeThreats,
    int UncoveredInScopeThreats,
    IReadOnlyList<ThreatCoverageListItem> UncoveredItems,
    IReadOnlyList<ThreatCatalogItem> PartialItems);

public sealed record PolicyEvaluationResult(
    string FinalAction,
    string FinalSeverity,
    IReadOnlyList<string> MatchedRules,
    IReadOnlyList<RuleTraceEntry> RuleTrace,
    IReadOnlyList<string> SideEffects,
    bool IsCovered,
    string? GapReason);
