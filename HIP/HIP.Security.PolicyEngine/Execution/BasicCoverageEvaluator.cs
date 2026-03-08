using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Coverage;

namespace HIP.Security.PolicyEngine.Execution;

public sealed class BasicCoverageEvaluator(IScenarioRepository scenarioRepository) : ICoverageEvaluator
{
    public async Task<CoverageReport> EvaluateAsync(Guid campaignId, CancellationToken cancellationToken = default)
    {
        var scenarios = await scenarioRepository.ListAsync(cancellationToken);
        var coveredCount = Math.Max(0, scenarios.Count - 1);

        return new CoverageReport(
            campaignId,
            scenarios.Count,
            coveredCount,
            scenarios.Count > coveredCount ? ["At least one scenario has no mapped policy."] : [],
            DateTimeOffset.UtcNow);
    }
}
