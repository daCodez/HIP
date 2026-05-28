namespace HIP.Domain.Rules;

public sealed record TrustRule(
    string Id,
    string Name,
    RuleStatus Status,
    RuleSeverity Severity,
    IReadOnlyCollection<RuleCondition> Conditions,
    RuleAction Action,
    decimal? SimulationConfidence,
    decimal? FalsePositiveRisk);
