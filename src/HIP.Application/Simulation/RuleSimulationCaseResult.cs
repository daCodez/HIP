namespace HIP.Application.Simulation;

public sealed record RuleSimulationCaseResult(
    string Name,
    bool Passed,
    bool ActualMatch,
    string? FailureReason,
    bool ExpectedMatch = false,
    string? ExpectedRiskLevel = null,
    bool? ExpectedSafetyPageRouting = null,
    IReadOnlyCollection<string>? InputFactKeys = null);
