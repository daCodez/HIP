using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Scenarios;

namespace HIP.Security.Infrastructure.Repositories;

public sealed class InMemoryScenarioRepository : IScenarioRepository
{
    private readonly List<ThreatScenario> _items = [];

    public Task<IReadOnlyList<ThreatScenario>> ListAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatScenario>>(_items);

    public Task AddAsync(ThreatScenario scenario, CancellationToken cancellationToken = default)
    {
        _items.Add(scenario);
        return Task.CompletedTask;
    }
}
