using HIP.Security.Domain.Scenarios;

namespace HIP.Security.Application.Abstractions.Repositories;

public interface IScenarioRepository
{
    Task<IReadOnlyList<ThreatScenario>> ListAsync(CancellationToken cancellationToken = default);
    Task AddAsync(ThreatScenario scenario, CancellationToken cancellationToken = default);
}
