using HIP.Security.Api.Contracts;
using HIP.Security.Api.Contracts.Policies;
using HIP.Security.Domain.Policies;

namespace HIP.Security.Api.Mappings;

public interface IPolicyDtoMapper
{
    IReadOnlyList<PolicyRule> ToDomainRules(CreatePolicyDraftRequest request);
    PolicyDto ToDto(SecurityPolicy policy);
}
