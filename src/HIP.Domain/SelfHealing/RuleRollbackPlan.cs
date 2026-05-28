namespace HIP.Domain.SelfHealing;

public sealed record RuleRollbackPlan(
    int? PreviousRuleVersion,
    string RollbackReason,
    string AffectedRuleId,
    bool CanRollback,
    DateTimeOffset CreatedAtUtc);
