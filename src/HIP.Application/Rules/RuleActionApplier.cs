using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class RuleActionApplier(IRuleMatchingEngine matchingEngine) : IRuleActionApplier
{
    public AppliedRuleResult Apply(TrustRule rule, FactSet facts)
    {
        var match = matchingEngine.Match(rule, facts);
        if (!match.IsMatch || rule.Mode == RuleMode.Watch)
        {
            return new AppliedRuleResult(rule, match.IsMatch, RiskStatus.Unknown, 0, [], false, false, rule.SimulationRequired);
        }

        var riskLevel = RiskStatus.Unknown;
        var scoreDelta = 0;
        var reasons = new List<string>();
        var routeToSafetyPage = false;
        var requiresReview = false;
        var markedForSimulation = rule.SimulationRequired;

        foreach (var action in rule.Actions)
        {
            switch (action.Type)
            {
                case RuleActionType.SetRiskLevel:
                    riskLevel = ParseRiskLevel(Text(action.Value), riskLevel);
                    break;
                case RuleActionType.AddScorePenalty:
                    scoreDelta -= Number(action.Value);
                    break;
                case RuleActionType.AddScoreBonus:
                    scoreDelta += Number(action.Value);
                    break;
                case RuleActionType.AddReason:
                case RuleActionType.AddWarning:
                    reasons.Add(Text(action.Value));
                    break;
                case RuleActionType.RouteToSafetyPage:
                    routeToSafetyPage = Boolean(action.Value);
                    break;
                case RuleActionType.Block:
                    riskLevel = RiskStatus.Critical;
                    routeToSafetyPage = true;
                    requiresReview = true;
                    reasons.Add("Rule action blocked this target.");
                    break;
                case RuleActionType.Allow:
                    riskLevel = RiskStatus.ProbablySafe;
                    routeToSafetyPage = false;
                    break;
                case RuleActionType.RequireReview:
                    requiresReview = Boolean(action.Value);
                    break;
                case RuleActionType.MarkForSimulation:
                    markedForSimulation = Boolean(action.Value);
                    break;
                case RuleActionType.AdjustScore:
                default:
                    break;
            }
        }

        return new AppliedRuleResult(rule, true, riskLevel, scoreDelta, reasons, routeToSafetyPage, requiresReview, markedForSimulation);
    }

    private static string Text(System.Text.Json.JsonElement value) =>
        value.ValueKind == System.Text.Json.JsonValueKind.String ? value.GetString() ?? string.Empty : value.ToString();

    private static int Number(System.Text.Json.JsonElement value) =>
        value.ValueKind == System.Text.Json.JsonValueKind.Number && value.TryGetInt32(out var number) ? number : 0;

    private static bool Boolean(System.Text.Json.JsonElement value) =>
        value.ValueKind switch
        {
            System.Text.Json.JsonValueKind.True => true,
            System.Text.Json.JsonValueKind.False => false,
            System.Text.Json.JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false
        };

    private static RiskStatus ParseRiskLevel(string value, RiskStatus fallback)
    {
        if (value.Equals("High", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("Suspicious", StringComparison.OrdinalIgnoreCase))
        {
            return RiskStatus.HighRisk;
        }

        return Enum.TryParse<RiskStatus>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }
}
