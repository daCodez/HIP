using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleActionApplier
{
    AppliedRuleResult Apply(TrustRule rule, FactSet facts);
}
