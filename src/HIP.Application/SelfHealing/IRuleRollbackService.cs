using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public interface IRuleRollbackService
{
    RuleRollbackPlan CreatePlan(string affectedRuleId, string rollbackReason, int? previousRuleVersion = null);
}
