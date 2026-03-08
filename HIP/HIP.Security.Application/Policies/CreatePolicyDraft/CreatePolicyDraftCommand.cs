using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Domain.Audit;
using HIP.Security.Domain.Policies;
using MediatR;

namespace HIP.Security.Application.Policies.CreatePolicyDraft;

public sealed record CreatePolicyDraftCommand(string Name, string Description, IReadOnlyList<PolicyRule> Rules) : IRequest<SecurityPolicy>;

public sealed class CreatePolicyDraftCommandHandler(
    IPolicyRepository policyRepository,
    IPolicyAuditRecorder auditRecorder) : IRequestHandler<CreatePolicyDraftCommand, SecurityPolicy>
{
    public async Task<SecurityPolicy> Handle(CreatePolicyDraftCommand request, CancellationToken cancellationToken)
    {
        var policy = new SecurityPolicy(Guid.NewGuid(), request.Name, request.Description, PolicyLifecycleState.Draft, request.Rules, DateTimeOffset.UtcNow);
        await policyRepository.AddAsync(policy, cancellationToken);

        await auditRecorder.RecordAsync(
            new PolicyAuditEvent(
                Guid.NewGuid(),
                policy.Id,
                "policy.create",
                "accepted",
                null,
                DateTimeOffset.UtcNow,
                new Dictionary<string, string>
                {
                    ["lifecycleState"] = policy.LifecycleState.ToString(),
                    ["rulesCount"] = policy.Rules.Count.ToString()
                }),
            cancellationToken);

        return policy;
    }
}
