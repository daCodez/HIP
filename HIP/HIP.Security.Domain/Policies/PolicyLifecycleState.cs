namespace HIP.Security.Domain.Policies;

/// <summary>Lifecycle state for a policy from initial draft through retirement.</summary>
public enum PolicyLifecycleState
{
    Draft = 0,
    Simulate = 1,
    Active = 2,
    Disabled = 3,
    Archived = 4
}
