namespace HIP.Application.Simulation;

public interface IRuleSimulationResultRepository
{
    Task SaveAsync(string simulationId, RuleSimulationResult result, CancellationToken cancellationToken);

    Task<RuleSimulationResult?> GetAsync(string simulationId, CancellationToken cancellationToken);
}
