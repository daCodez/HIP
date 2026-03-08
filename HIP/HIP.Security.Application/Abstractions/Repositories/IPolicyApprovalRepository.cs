using HIP.Security.Domain.Approvals;

namespace HIP.Security.Application.Abstractions.Repositories;

public interface IPolicyApprovalRepository
{
    Task UpsertAsync(Guid policyId, PolicyApprovalMetadata metadata, CancellationToken cancellationToken = default);
    Task<PolicyApprovalMetadata?> GetByPolicyIdAsync(Guid policyId, CancellationToken cancellationToken = default);
}
