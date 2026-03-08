using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Application.Abstractions.Generation;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticTelemetrySuggestionGenerator(ICoverageEvaluator coverageEvaluator) : ITelemetrySuggestionGenerator
{
    public async Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default)
    {
        var coverage = await coverageEvaluator.EvaluateAsync(campaignId, cancellationToken);
        var tasks = new List<string>
        {
            $"[Campaign {campaignId:N}] Emit simulator.run.coverage_percent={coverage.CoveragePercent}."
        };

        tasks.AddRange(coverage.Gaps
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .Select((gap, idx) => $"[Campaign {campaignId:N}] Gap {idx + 1}: add telemetry marker for '{gap}'."));

        if (tasks.Count == 1)
        {
            tasks.Add($"[Campaign {campaignId:N}] Track policy decision latency p95 and p99 by scenario tag.");
        }

        return tasks;
    }
}
