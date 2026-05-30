using System.Collections.Concurrent;

namespace HIP.Application.Simulation;

public sealed class InMemoryRuleSimulationResultRepository : IRuleSimulationResultRepository
{
    private readonly ConcurrentDictionary<string, RuleSimulationResult> _results = new(StringComparer.OrdinalIgnoreCase);

    public Task SaveAsync(string simulationId, RuleSimulationResult result, CancellationToken cancellationToken)
    {
        _results[simulationId] = result;
        return Task.CompletedTask;
    }

    public Task<RuleSimulationResult?> GetAsync(string simulationId, CancellationToken cancellationToken)
    {
        _results.TryGetValue(simulationId, out var result);
        return Task.FromResult(result);
    }
}
