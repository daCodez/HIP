using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed class RuleRollbackService : IRuleRollbackService
{
    public RuleRollbackPlan CreatePlan(string affectedRuleId, string rollbackReason, int? previousRuleVersion = null) =>
        new(
            previousRuleVersion,
            string.IsNullOrWhiteSpace(rollbackReason) ? "Revert generated self-healing rule if false positives increase." : rollbackReason,
            affectedRuleId,
            !string.IsNullOrWhiteSpace(affectedRuleId),
            DateTimeOffset.UtcNow);
}
