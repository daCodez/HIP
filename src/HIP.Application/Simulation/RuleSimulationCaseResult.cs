namespace HIP.Application.Simulation;

public sealed record RuleSimulationCaseResult(
    string Name,
    bool Passed,
    bool ActualMatch,
    string? FailureReason);
