using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Application.Abstractions.Policies;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Application.Policies.Internal;
using HIP.Security.Domain.Approvals;
using HIP.Security.Domain.Audit;
using HIP.Security.Domain.Policies;
using MediatR;

namespace HIP.Security.Application.Policies.ActivatePolicy;

public sealed record ActivatePolicyCommand(Guid PolicyId, PolicyApprovalMetadata ApprovalMetadata) : IRequest<SecurityPolicy>;

public sealed class ActivatePolicyCommandHandler(
    IPolicyRepository policyRepository,
    IPolicyApprovalRepository approvalRepository,
    IPolicyLifecycleGuard lifecycleGuard,
    IPolicyAuditRecorder auditRecorder) : IRequestHandler<ActivatePolicyCommand, SecurityPolicy>
{
    public async Task<SecurityPolicy> Handle(ActivatePolicyCommand request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ApprovalMetadata.AuthorId)
            || string.IsNullOrWhiteSpace(request.ApprovalMetadata.ReviewerId)
            || string.IsNullOrWhiteSpace(request.ApprovalMetadata.ApproverId))
        {
            throw new PolicyTransitionRejectedException(
                "Activation requires author/reviewer/approver metadata.",
                PolicyTransitionRejectReasonCode.ApprovalMetadataRequired);
        }

        var existing = await policyRepository.GetByIdAsync(request.PolicyId, cancellationToken)
            ?? throw new InvalidOperationException($"Policy '{request.PolicyId}' was not found.");

        var activated = lifecycleGuard.TransitionToActive(existing);
        await approvalRepository.UpsertAsync(request.PolicyId, request.ApprovalMetadata, cancellationToken);
        await policyRepository.UpdateAsync(activated, cancellationToken);

        await auditRecorder.RecordAsync(
            new PolicyAuditEvent(
                Guid.NewGuid(),
                activated.Id,
                "policy.activate",
                "accepted",
                null,
                DateTimeOffset.UtcNow,
                new Dictionary<string, string>
                {
                    ["reviewerId"] = request.ApprovalMetadata.ReviewerId,
                    ["approverId"] = request.ApprovalMetadata.ApproverId,
                    ["lifecycleState"] = activated.LifecycleState.ToString()
                }),
            cancellationToken);

        return activated;
    }
}
