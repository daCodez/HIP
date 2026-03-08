using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Threats;

namespace HIP.Security.Infrastructure.Repositories;

public sealed class InMemoryThreatRepository : IThreatRepository
{
    private readonly List<ThreatModel> _items = [];

    public Task<IReadOnlyList<ThreatModel>> ListAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<ThreatModel>>(_items);

    public Task AddAsync(ThreatModel threat, CancellationToken cancellationToken = default)
    {
        _items.Add(threat);
        return Task.CompletedTask;
    }
}
