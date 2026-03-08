using HIP.Simulator.Core.Models;

namespace HIP.Admin.Models;

public sealed record SimulatorRecommendationTask(
    string RecommendationId,
    string Kind,
    string Title,
    string Detail,
    PolicySuggestion Suggestion,
    string SourceKey);

public sealed record SimulatorRecommendationResponse(
    string RunId,
    int Total,
    IReadOnlyList<SimulatorRecommendationTask> ScenarioTasks,
    IReadOnlyList<SimulatorRecommendationTask> TelemetryTasks);

public sealed record AutoFixAllRequest(string? IdempotencyKey);

public sealed record AutoFixAllApplyDetail(
    string RecommendationId,
    string RuleId,
    string Outcome,
    string Message);

public sealed record AutoFixAllApplySummary(
    string RunId,
    string IdempotencyKey,
    int Attempted,
    int Created,
    int Skipped,
    int Failed,
    IReadOnlyList<AutoFixAllApplyDetail> Details);