namespace HIP.Application.Rules;

public static class RuleValidationConstants
{
    public static bool IsHighImpact(HIP.Domain.Rules.TrustRule rule) =>
        rule.Severity is HIP.Domain.Rules.RuleSeverity.Dangerous or HIP.Domain.Rules.RuleSeverity.Critical ||
        (rule.Mode == HIP.Domain.Rules.RuleMode.Active &&
         rule.Severity is HIP.Domain.Rules.RuleSeverity.HighRisk or HIP.Domain.Rules.RuleSeverity.Dangerous or HIP.Domain.Rules.RuleSeverity.Critical);
}
