using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public interface IRuleEvaluationService
{
    RuleEvaluationResponse Evaluate(IReadOnlyCollection<TrustRule> rules, RuleScanContext context);

    FactSet ToFactSet(RuleScanContext context);
}
