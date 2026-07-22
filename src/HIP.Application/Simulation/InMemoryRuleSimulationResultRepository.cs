using System.Collections.Concurrent;

namespace HIP.Application.Simulation;

public sealed class InMemoryRuleSimulationResultRepository : IRuleSimulationResultRepository
{
    private readonly ConcurrentDictionary<string, RuleSimulationResult> _results = new(StringComparer.OrdinalIgnoreCase);

    public Task SaveAsync(string simulationId, RuleSimulationResult result, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RuleSimulationResultContract.Validate(result);
        if (!string.Equals(simulationId, result.SimulationId, StringComparison.Ordinal) ||
            !_results.TryAdd(simulationId, result))
        {
            throw new InvalidOperationException("A simulation result is immutable and cannot be overwritten.");
        }
        return Task.CompletedTask;
    }

    public Task<RuleSimulationResult?> GetAsync(string simulationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(simulationId) || simulationId.Length > 128 || simulationId.Any(char.IsControl))
        {
            return Task.FromResult<RuleSimulationResult?>(null);
        }
        _results.TryGetValue(simulationId, out var result);
        return Task.FromResult(result);
    }
}
