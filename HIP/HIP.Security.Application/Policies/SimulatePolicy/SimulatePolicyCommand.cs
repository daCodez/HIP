using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Application.Abstractions.Policies;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Application.Policies.Internal;
using HIP.Security.Domain.Audit;
using HIP.Security.Domain.Policies;
using MediatR;

namespace HIP.Security.Application.Policies.SimulatePolicy;

public sealed record SimulatePolicyCommand(Guid PolicyId) : IRequest<SecurityPolicy>;

public sealed class SimulatePolicyCommandHandler(
    IPolicyRepository policyRepository,
    IPolicyLifecycleGuard lifecycleGuard,
    IPolicyAuditRecorder auditRecorder) : IRequestHandler<SimulatePolicyCommand, SecurityPolicy>
{
    public async Task<SecurityPolicy> Handle(SimulatePolicyCommand request, CancellationToken cancellationToken)
    {
        var existing = await policyRepository.GetByIdAsync(request.PolicyId, cancellationToken)
            ?? throw new InvalidOperationException($"Policy '{request.PolicyId}' was not found.");

        var simulated = lifecycleGuard.TransitionToSimulate(existing);
        if (simulated != existing)
        {
            await policyRepository.UpdateAsync(simulated, cancellationToken);
        }

        await auditRecorder.RecordAsync(
            new PolicyAuditEvent(
                Guid.NewGuid(),
                simulated.Id,
                "policy.simulate",
                "accepted",
                null,
                DateTimeOffset.UtcNow,
                new Dictionary<string, string>
                {
                    ["lifecycleState"] = simulated.LifecycleState.ToString()
                }),
            cancellationToken);

        return simulated;
    }
}
