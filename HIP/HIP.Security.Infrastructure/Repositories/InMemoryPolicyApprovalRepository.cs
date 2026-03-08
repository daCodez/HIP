using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Approvals;

namespace HIP.Security.Infrastructure.Repositories;

public sealed class InMemoryPolicyApprovalRepository : IPolicyApprovalRepository
{
    private readonly Dictionary<Guid, PolicyApprovalMetadata> _items = [];

    public Task UpsertAsync(Guid policyId, PolicyApprovalMetadata metadata, CancellationToken cancellationToken = default)
    {
        _items[policyId] = metadata;
        return Task.CompletedTask;
    }

    public Task<PolicyApprovalMetadata?> GetByPolicyIdAsync(Guid policyId, CancellationToken cancellationToken = default)
    {
        _items.TryGetValue(policyId, out var metadata);
        return Task.FromResult(metadata);
    }
}
