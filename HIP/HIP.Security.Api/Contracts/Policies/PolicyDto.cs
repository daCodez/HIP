namespace HIP.Security.Api.Contracts.Policies;

public sealed record PolicyDto(
    Guid Id,
    string Name,
    string Description,
    string LifecycleState,
    IReadOnlyList<PolicyRuleDto> Rules,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? LastModifiedAtUtc);
