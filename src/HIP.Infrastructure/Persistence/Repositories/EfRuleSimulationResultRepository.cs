using HIP.Application.Simulation;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRuleSimulationResultRepository(HipRecordStore store) : IRuleSimulationResultRepository
{
    private const string Partition = "rule-simulation-result";

    public async Task SaveAsync(string simulationId, RuleSimulationResult result, CancellationToken cancellationToken)
    {
        RuleSimulationResultContract.Validate(result);
        if (!string.Equals(simulationId, result.SimulationId, StringComparison.Ordinal) ||
            !await store.TrySaveVersionedAsync(Partition, simulationId, result, 0, 1, cancellationToken))
        {
            throw new InvalidOperationException("A simulation result is immutable and cannot be overwritten.");
        }
    }

    public async Task<RuleSimulationResult?> GetAsync(string simulationId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(simulationId) || simulationId.Length > 128 ||
            simulationId.Any(char.IsControl))
        {
            return null;
        }
        var stored = await store.GetVersionedAsync<RuleSimulationResult>(Partition, simulationId, cancellationToken);
        if (stored is null)
        {
            return null;
        }
        if (stored.Value.AggregateVersion == 0)
        {
            // HIP-0403 preserves read compatibility for results stored before immutable versioning.
            return stored.Value.Record;
        }
        RuleSimulationResultContract.Validate(stored.Value.Record);
        return stored.Value.AggregateVersion == stored.Value.Record.Version
            ? stored.Value.Record
            : throw new InvalidOperationException("Simulation result version is inconsistent.");
    }
}
