using System.Text.Json;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class RuleEvaluationService(
    IRuleMatchingEngine matchingEngine,
    IRuleActionApplier actionApplier) : IRuleEvaluationService
{
    public RuleEvaluationResponse Evaluate(IReadOnlyCollection<TrustRule> rules, RuleScanContext context)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(context);

        var facts = ToFactSet(context);
        var matchedRules = new List<string>();
        var actions = new List<RuleActionSummary>();
        var reasons = new List<string>();
        var watchModeResults = new List<RuleEvaluationItem>();
        var enforcementResults = new List<RuleEvaluationItem>();
        var riskLevel = RiskStatus.Unknown;
        var shouldRoute = false;
        var shouldBlock = false;
        var requiresReview = false;

        foreach (var rule in rules)
        {
            var match = matchingEngine.Match(rule, facts);
            if (!match.IsMatch)
            {
                continue;
            }

            matchedRules.Add(rule.RuleId);
            var actionSummaries = rule.Actions.Select(action => new RuleActionSummary(action.Type, ValueText(action.Value))).ToArray();
            actions.AddRange(actionSummaries);

            if (rule.Mode == RuleMode.Watch)
            {
                watchModeResults.Add(new RuleEvaluationItem(rule.RuleId, rule.Name, rule.Mode, true, actionSummaries, ReasonActions(rule).ToArray(), false));
                continue;
            }

            var applied = actionApplier.Apply(rule, facts);
            reasons.AddRange(applied.Reasons);
            shouldRoute |= applied.ShouldRouteToSafetyPage;
            requiresReview |= applied.RequiresReview;
            shouldBlock |= rule.Actions.Any(action => action.Type == RuleActionType.Block);
            riskLevel = HighestRisk(riskLevel, applied.RiskLevel);

            enforcementResults.Add(new RuleEvaluationItem(rule.RuleId, rule.Name, rule.Mode, true, actionSummaries, applied.Reasons, true));
        }

        return new RuleEvaluationResponse(
            matchedRules,
            actions,
            riskLevel,
            reasons.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            watchModeResults,
            enforcementResults,
            shouldRoute,
            shouldBlock,
            requiresReview);
    }

    public FactSet ToFactSet(RuleScanContext context) => new(new Dictionary<string, object?>
    {
        ["url"] = context.Url,
        ["domain.name"] = context.Domain,
        ["domain.ageDays"] = context.DomainAgeDays,
        ["domain.score"] = context.DomainScore,
        ["domain.reputationScore"] = context.DomainScore,
        ["url.usesShortener"] = context.UsesShortener,
        ["url.isObfuscated"] = context.HasObfuscation,
        ["url.redirectCount"] = context.RedirectCount,
        ["url.hasKnownRisk"] = context.DomainScore <= 40,
        ["sender.score"] = context.SenderScore,
        ["sender.reputationScore"] = context.SenderScore,
        ["content.riskScore"] = context.ContentRiskScore,
        ["content.containsUrgencyLanguage"] = context.ContentRiskScore >= 60,
        ["content.containsFinancialPromise"] = context.ContentRiskScore >= 70,
        ["identity.signatureValid"] = false
    });

    private static IEnumerable<string> ReasonActions(TrustRule rule) =>
        rule.Actions
            .Where(action => action.Type is RuleActionType.AddReason or RuleActionType.AddWarning)
            .Select(action => ValueText(action.Value));

    private static string ValueText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.True => bool.TrueString,
        JsonValueKind.False => bool.FalseString,
        _ => value.ToString()
    };

    private static RiskStatus HighestRisk(RiskStatus current, RiskStatus candidate) =>
        RiskWeight(candidate) > RiskWeight(current) ? candidate : current;

    private static int RiskWeight(RiskStatus status) => status switch
    {
        RiskStatus.Trusted => 1,
        RiskStatus.ProbablySafe => 2,
        RiskStatus.Caution => 3,
        RiskStatus.HighRisk => 4,
        RiskStatus.Dangerous => 5,
        RiskStatus.Critical => 6,
        _ => 0
    };
}
