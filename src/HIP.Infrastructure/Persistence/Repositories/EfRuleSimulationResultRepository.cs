using HIP.Application.Simulation;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRuleSimulationResultRepository(HipRecordStore store) : IRuleSimulationResultRepository
{
    private const string Partition = "rule-simulation-result";

    public Task SaveAsync(string simulationId, RuleSimulationResult result, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, simulationId, result, cancellationToken);

    public Task<RuleSimulationResult?> GetAsync(string simulationId, CancellationToken cancellationToken) =>
        store.GetAsync<RuleSimulationResult>(Partition, simulationId, cancellationToken);
}
