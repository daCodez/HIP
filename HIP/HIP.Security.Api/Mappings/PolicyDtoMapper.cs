using HIP.Security.Api.Contracts;
using HIP.Security.Api.Contracts.Policies;
using HIP.Security.Domain.Policies;

namespace HIP.Security.Api.Mappings;

public sealed class PolicyDtoMapper : IPolicyDtoMapper
{
    public IReadOnlyList<PolicyRule> ToDomainRules(CreatePolicyDraftRequest request) =>
        request.Rules.Select(x => new PolicyRule(x.Key, x.Operator, x.Value)).ToArray();

    public PolicyDto ToDto(SecurityPolicy policy) =>
        new(
            policy.Id,
            policy.Name,
            policy.Description,
            policy.LifecycleState.ToString(),
            policy.Rules.Select(x => new PolicyRuleDto(x.Key, x.Operator, x.Value)).ToArray(),
            policy.CreatedAtUtc,
            policy.LastModifiedAtUtc);
}
