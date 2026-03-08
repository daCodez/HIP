namespace HIP.Security.Domain.Policies;

public sealed record SecurityPolicy(
    Guid Id,
    string Name,
    string Description,
    PolicyLifecycleState LifecycleState,
    IReadOnlyList<PolicyRule> Rules,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? LastModifiedAtUtc = null);
