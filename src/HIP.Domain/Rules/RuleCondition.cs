namespace HIP.Domain.Rules;

public sealed record RuleCondition(string Field, RuleOperator Operator, string Value);
