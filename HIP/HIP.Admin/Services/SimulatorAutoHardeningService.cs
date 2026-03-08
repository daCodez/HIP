using System.Collections.Concurrent;
using HIP.Admin.Models;
using HIP.Simulator.Core.Models;

namespace HIP.Admin.Services;

public interface ISimulatorAutoHardeningIdempotencyStore
{
    bool TryGet(string key, out AutoFixAllApplySummary summary);
    AutoFixAllApplySummary Store(string key, AutoFixAllApplySummary summary);
}

public sealed class InMemorySimulatorAutoHardeningIdempotencyStore : ISimulatorAutoHardeningIdempotencyStore
{
    private readonly ConcurrentDictionary<string, AutoFixAllApplySummary> _entries = new(StringComparer.OrdinalIgnoreCase);

    public bool TryGet(string key, out AutoFixAllApplySummary summary) => _entries.TryGetValue(key, out summary!);

    public AutoFixAllApplySummary Store(string key, AutoFixAllApplySummary summary)
    {
        _entries[key] = summary;
        return summary;
    }
}

public sealed class SimulatorAutoHardeningService(SimulatorAdminService simulatorService, HipAdminApiClient apiClient, ISimulatorAutoHardeningIdempotencyStore idempotencyStore)
{
    public SimulatorRecommendationResponse GetRecommendations(string runId)
    {
        var run = simulatorService.GetRun(runId);
        if (run.Result is null)
        {
            return new SimulatorRecommendationResponse(runId, 0, [], []);
        }

        var scenarioTasks = BuildScenarioTasks(run.Result, run.ThreatCoverage);
        var telemetryTasks = BuildTelemetryTasks(run.Result, run.ThreatCoverage);

        return new SimulatorRecommendationResponse(
            runId,
            scenarioTasks.Count + telemetryTasks.Count,
            scenarioTasks,
            telemetryTasks);
    }

    public Task<AutoFixAllApplySummary> AutoFixAllAsync(string runId, string? idempotencyKey, CancellationToken cancellationToken = default)
        => ApplyRecommendationsAsync(runId, idempotencyKey, "autofix-all", static r => r.ScenarioTasks.Concat(r.TelemetryTasks), cancellationToken);

    public Task<AutoFixAllApplySummary> GenerateScenarioDraftsAsync(string runId, string? idempotencyKey, CancellationToken cancellationToken = default)
        => ApplyRecommendationsAsync(runId, idempotencyKey, "generate-scenarios", static r => r.ScenarioTasks, cancellationToken);

    public Task<AutoFixAllApplySummary> AddTelemetryDraftsAsync(string runId, string? idempotencyKey, CancellationToken cancellationToken = default)
        => ApplyRecommendationsAsync(runId, idempotencyKey, "add-telemetry", static r => r.TelemetryTasks, cancellationToken);

    private async Task<AutoFixAllApplySummary> ApplyRecommendationsAsync(
        string runId,
        string? idempotencyKey,
        string operation,
        Func<SimulatorRecommendationResponse, IEnumerable<SimulatorRecommendationTask>> selector,
        CancellationToken cancellationToken)
    {
        var effectiveKey = string.IsNullOrWhiteSpace(idempotencyKey)
            ? $"run:{runId}:{operation}"
            : $"run:{runId}:{operation}:{idempotencyKey.Trim()}";

        if (idempotencyStore.TryGet(effectiveKey, out var existing))
        {
            return existing;
        }

        var recommendations = GetRecommendations(runId);
        var selected = selector(recommendations)
            .OrderBy(x => x.RecommendationId, StringComparer.Ordinal)
            .ToArray();

        var details = new List<AutoFixAllApplyDetail>(selected.Length);
        var created = 0;
        var failed = 0;

        foreach (var item in selected)
        {
            var normalized = BuildDraftSafeRule(item.Suggestion, item.RecommendationId);
            var save = await apiClient.UpsertPolicyRuleAsync(normalized, cancellationToken);
            if (save.Success)
            {
                created++;
                details.Add(new AutoFixAllApplyDetail(item.RecommendationId, normalized.RuleId, "created", "Draft rule created with Enabled=false."));
            }
            else
            {
                failed++;
                details.Add(new AutoFixAllApplyDetail(item.RecommendationId, normalized.RuleId, "failed", save.Error ?? "Policy API rejected the recommendation."));
            }
        }

        var summary = new AutoFixAllApplySummary(
            runId,
            effectiveKey,
            Attempted: selected.Length,
            Created: created,
            Skipped: 0,
            Failed: failed,
            Details: details);

        return idempotencyStore.Store(effectiveKey, summary);
    }

    private static List<SimulatorRecommendationTask> BuildScenarioTasks(SimulationRunResult run, ThreatCoverageSummary? threatCoverage)
    {
        var tasks = run.Scenarios
            .Where(x => x.Suggestion is not null)
            .OrderBy(x => x.ScenarioId, StringComparer.OrdinalIgnoreCase)
            .Select(x => new SimulatorRecommendationTask(
                RecommendationId: $"scenario:{x.ScenarioId}",
                Kind: "scenario",
                Title: $"Harden scenario '{x.ScenarioId}'",
                Detail: x.Suggestion!.Reason,
                Suggestion: EnsureDraftSafeSuggestion(x.Suggestion!),
                SourceKey: x.ScenarioId))
            .ToList();

        if (tasks.Count > 0)
        {
            return tasks;
        }

        if (threatCoverage?.UncoveredItems is null)
        {
            return tasks;
        }

        var fallbackThreats = threatCoverage.UncoveredItems
            .OrderByDescending(x => x.IsInScope)
            .ThenBy(x => x.Threat.ThreatId, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.Threat)
            .ToList();

        tasks.AddRange(fallbackThreats
            .Select(threat => new SimulatorRecommendationTask(
                RecommendationId: $"threat:{threat.ThreatId}",
                Kind: "scenario",
                Title: $"Cover uncovered threat '{threat.ThreatId}'",
                Detail: threat.Title,
                Suggestion: BuildFallbackSuggestionFromThreat(threat),
                SourceKey: threat.ThreatId)));

        return tasks;
    }

    private static List<SimulatorRecommendationTask> BuildTelemetryTasks(SimulationRunResult run, ThreatCoverageSummary? threatCoverage)
    {
        var signals = run.Scenarios
            .Where(x => x.Suggestion is not null)
            .SelectMany(x => x.Suggestion!.NeededSignals)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (signals.Count == 0)
        {
            var fallbackSignals = threatCoverage?.UncoveredItems.SelectMany(_ => new[] { "threatTaxonomyId", "eventType", "actorId" }).ToList()
                ?? [];
            signals.AddRange(fallbackSignals.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
        }

        return signals
            .Select(signal => new SimulatorRecommendationTask(
                RecommendationId: $"telemetry:{signal.ToLowerInvariant()}",
                Kind: "telemetry",
                Title: $"Capture telemetry signal '{signal}'",
                Detail: "Add this signal to simulator-backed event payloads for more accurate policy tuning.",
                Suggestion: new PolicySuggestion(
                    RuleName: $"Sim.Telemetry.{SanitizeId(signal)}.Draft",
                    Category: "system",
                    ConditionExpression: $"hasSignal('{signal}') == false",
                    RecommendedAction: "Alert",
                    RecommendedSeverity: "Low",
                    Reason: $"Telemetry gap detected for '{signal}'.",
                    NeededSignals: [signal],
                    PositiveTestCase: $"Event payload includes '{signal}'.",
                    NegativeTestCase: $"Event payload missing '{signal}'.",
                    Notes: "Draft-safe telemetry recommendation. Keep disabled until validated in production-like traffic."),
                SourceKey: signal))
            .ToList();
    }

    private static PolicyRule BuildDraftSafeRule(PolicySuggestion suggestion, string recommendationId)
        => new()
        {
            RuleId = $"SIM-{SanitizeId(recommendationId)}",
            Name = $"{suggestion.RuleName} (Draft)",
            Category = NormalizeCategory(suggestion.Category),
            Condition = suggestion.ConditionExpression,
            Action = suggestion.RecommendedAction,
            Severity = NormalizeSeverity(suggestion.RecommendedSeverity),
            Enabled = false
        };

    private static PolicySuggestion EnsureDraftSafeSuggestion(PolicySuggestion suggestion)
        => suggestion with
        {
            RuleName = suggestion.RuleName.EndsWith(".Draft", StringComparison.OrdinalIgnoreCase)
                ? suggestion.RuleName
                : $"{suggestion.RuleName}.Draft",
            Notes = string.IsNullOrWhiteSpace(suggestion.Notes)
                ? "Draft-safe recommendation generated by simulator run. Review before enabling."
                : suggestion.Notes
        };

    private static PolicySuggestion BuildFallbackSuggestionFromThreat(ThreatCatalogItem threat)
    {
        var normalizedThreatId = threat.ThreatId.Trim().ToUpperInvariant();
        var severity = threat.Severity.Trim().ToLowerInvariant() switch
        {
            "critical" or "high" => "High",
            "low" => "Low",
            _ => "Medium"
        };

        return new PolicySuggestion(
            RuleName: $"Sim.Threat.{normalizedThreatId}.Draft",
            Category: "uncovered",
            ConditionExpression: $"threatTaxonomyId == '{normalizedThreatId}'",
            RecommendedAction: severity == "High" ? "Challenge" : "Alert",
            RecommendedSeverity: severity,
            Reason: $"Uncovered taxonomy threat: {threat.Title}",
            NeededSignals: ["threatTaxonomyId", "eventType", "actorId"],
            PositiveTestCase: $"{normalizedThreatId} event is detected and challenged.",
            NegativeTestCase: $"Events unrelated to {normalizedThreatId} are not challenged.",
            Notes: "Draft-safe fallback suggestion generated from uncovered taxonomy threats.");
    }

    private static string NormalizeCategory(string? category)
        => category?.Trim().ToLowerInvariant() switch
        {
            "authentication" => "Login",
            "device" => "Device",
            "token" => "Token",
            "messaging" => "Messaging",
            "reputation" => "Reputation",
            "session" => "Session",
            "uncovered" => "Risk",
            "invalid" => "System",
            "risk" => "Risk",
            "system" => "System",
            _ => "Risk"
        };

    private static string NormalizeSeverity(string? severity)
        => severity?.Trim().ToLowerInvariant() switch
        {
            "critical" => "Critical",
            "high" => "High",
            "low" => "Low",
            _ => "Medium"
        };

    private static string SanitizeId(string value)
    {
        var chars = value
            .Trim()
            .ToUpperInvariant()
            .Select(ch => char.IsLetterOrDigit(ch) ? ch : '-')
            .ToArray();

        return string.Join(string.Empty, chars).Trim('-');
    }
}
