namespace HIP.Domain.Rules;

public sealed record TrustRule(
    string RuleId,
    string Name,
    string Description,
    bool Enabled,
    RuleMode Mode,
    RuleSeverity Severity,
    IReadOnlyCollection<RuleCondition> Conditions,
    IReadOnlyCollection<RuleAction> Actions,
    bool RequiresApproval,
    bool SimulationRequired,
    string CreatedBy,
    string CreatedReason,
    ApprovalStatus ApprovalStatus,
    decimal ConfidenceScore,
    int Version);
