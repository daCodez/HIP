using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Application.Abstractions.Generation;
using HIP.Security.Application.Abstractions.Repositories;

namespace HIP.Security.Infrastructure.Generation;

public sealed class StaticPolicySuggestionGenerator(ICoverageEvaluator coverageEvaluator, IThreatRepository threatRepository) : IPolicySuggestionGenerator
{
    public async Task<IReadOnlyList<string>> GenerateAsync(Guid campaignId, CancellationToken cancellationToken = default)
    {
        var coverage = await coverageEvaluator.EvaluateAsync(campaignId, cancellationToken);
        var threats = await threatRepository.ListAsync(cancellationToken);

        var tasks = new List<string>();

        if (coverage.Gaps.Count > 0)
        {
            tasks.AddRange(coverage.Gaps
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .Select(gap => $"[Campaign {campaignId:N}] Create draft-disabled policy for coverage gap: {gap}."));
        }

        tasks.AddRange(threats
            .OrderByDescending(x => x.Severity, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Take(3)
            .Select(x => $"[Campaign {campaignId:N}] Create draft-disabled policy for threat '{x.Name}' ({x.Severity})."));

        if (tasks.Count == 0)
        {
            tasks.Add($"[Campaign {campaignId:N}] Create draft-disabled policy: adaptive throttle on repeated token replay attempts.");
        }

        return tasks;
    }
}
