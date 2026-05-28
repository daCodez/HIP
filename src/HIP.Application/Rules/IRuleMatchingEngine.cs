using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleMatchingEngine
{
    RuleMatchResult Match(TrustRule rule, FactSet facts);
}
