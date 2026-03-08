using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Application.Policies.Internal;
using HIP.Security.Domain.Audit;
using MediatR;

namespace HIP.Security.Application.Policies.RollbackPolicy;

public sealed record RollbackPolicyCommand(Guid PolicyId, string RequestedBy) : IRequest<string>;

public sealed class RollbackPolicyCommandHandler(
    IPolicyRepository policyRepository,
    IPolicyAuditRecorder auditRecorder) : IRequestHandler<RollbackPolicyCommand, string>
{
    public async Task<string> Handle(RollbackPolicyCommand request, CancellationToken cancellationToken)
    {
        var existing = await policyRepository.GetByIdAsync(request.PolicyId, cancellationToken)
            ?? throw new InvalidOperationException($"Policy '{request.PolicyId}' was not found.");

        await auditRecorder.RecordAsync(
            new PolicyAuditEvent(
                Guid.NewGuid(),
                existing.Id,
                "policy.rollback",
                "rejected",
                PolicyTransitionRejectReasonCode.RollbackNotSupported.ToString(),
                DateTimeOffset.UtcNow,
                new Dictionary<string, string>
                {
                    ["requestedBy"] = request.RequestedBy,
                    ["lifecycleState"] = existing.LifecycleState.ToString()
                }),
            cancellationToken);

        throw new PolicyTransitionRejectedException(
            "Rollback scaffolding is present, but rollback execution is intentionally disabled in Phase 2B.",
            PolicyTransitionRejectReasonCode.RollbackNotSupported);
    }
}
