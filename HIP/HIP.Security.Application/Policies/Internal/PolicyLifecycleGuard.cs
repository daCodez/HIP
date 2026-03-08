using HIP.Security.Application.Abstractions.Policies;
using HIP.Security.Domain.Policies;

namespace HIP.Security.Application.Policies.Internal;

public sealed class PolicyLifecycleGuard : IPolicyLifecycleGuard
{
    public SecurityPolicy TransitionToSimulate(SecurityPolicy policy)
    {
        if (policy.LifecycleState is PolicyLifecycleState.Disabled or PolicyLifecycleState.Archived)
        {
            throw new PolicyTransitionRejectedException(
                $"Policy '{policy.Id}' cannot move to Simulate from '{policy.LifecycleState}'.",
                PolicyTransitionRejectReasonCode.UnsupportedSourceState);
        }

        return policy.LifecycleState switch
        {
            PolicyLifecycleState.Simulate => policy,
            PolicyLifecycleState.Draft => policy with
            {
                LifecycleState = PolicyLifecycleState.Simulate,
                LastModifiedAtUtc = DateTimeOffset.UtcNow
            },
            PolicyLifecycleState.Active => throw new PolicyTransitionRejectedException(
                $"Policy '{policy.Id}' is already Active and cannot move backwards to Simulate.",
                PolicyTransitionRejectReasonCode.AutoPromotionDisallowed),
            _ => throw new PolicyTransitionRejectedException(
                $"Policy '{policy.Id}' has unsupported lifecycle state '{policy.LifecycleState}'.",
                PolicyTransitionRejectReasonCode.UnsupportedSourceState)
        };
    }

    public SecurityPolicy TransitionToActive(SecurityPolicy policy)
    {
        if (policy.LifecycleState is PolicyLifecycleState.Disabled or PolicyLifecycleState.Archived)
        {
            throw new PolicyTransitionRejectedException(
                $"Policy '{policy.Id}' cannot be activated from '{policy.LifecycleState}'.",
                PolicyTransitionRejectReasonCode.UnsupportedSourceState);
        }

        if (policy.LifecycleState is not PolicyLifecycleState.Simulate)
        {
            throw new PolicyTransitionRejectedException(
                $"Policy '{policy.Id}' must be in Simulate before activation. Current state: '{policy.LifecycleState}'.",
                PolicyTransitionRejectReasonCode.RequiresSimulationStage);
        }

        return policy with
        {
            LifecycleState = PolicyLifecycleState.Active,
            LastModifiedAtUtc = DateTimeOffset.UtcNow
        };
    }
}
