using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Policies;

namespace HIP.Security.Infrastructure.Repositories;

public sealed class InMemoryPolicyRepository : IPolicyRepository
{
    private readonly List<SecurityPolicy> _items = [];

    public Task<IReadOnlyList<SecurityPolicy>> ListAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<SecurityPolicy>>(_items);

    public Task<SecurityPolicy?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        Task.FromResult(_items.FirstOrDefault(p => p.Id == id));

    public Task AddAsync(SecurityPolicy policy, CancellationToken cancellationToken = default)
    {
        _items.Add(policy);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(SecurityPolicy policy, CancellationToken cancellationToken = default)
    {
        var index = _items.FindIndex(p => p.Id == policy.Id);
        if (index >= 0)
        {
            _items[index] = policy;
        }

        return Task.CompletedTask;
    }
}
