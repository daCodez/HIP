using System.Text.Json;
using HIP.Application.Rules;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

public sealed class RuleEngineTests
{
    [Test]
    public void RuleMatchingEngine_matches_all_conditions()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active);
        var facts = new FactSet(new Dictionary<string, object?>
        {
            ["domain.ageDays"] = 12,
            ["url.usesShortener"] = true
        });

        var result = new RuleMatchingEngine().Match(rule, facts);

        Assert.That(result.IsMatch, Is.True);
        Assert.That(result.FailedFields, Is.Empty);
    }

    [Test]
    public void RuleActionApplier_applies_risk_level_penalty_reason_and_safety_route()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active);
        var facts = new FactSet(new Dictionary<string, object?>
        {
            ["domain.ageDays"] = 12,
            ["url.usesShortener"] = true
        });

        var result = new RuleActionApplier(new RuleMatchingEngine()).Apply(rule, facts);

        Assert.That(result.IsMatch, Is.True);
        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.HighRisk));
        Assert.That(result.ScoreDelta, Is.EqualTo(-25));
        Assert.That(result.ShouldRouteToSafetyPage, Is.True);
        Assert.That(result.Reasons.Single(), Does.Contain("shortened"));
    }

    [Test]
    public void Valid_json_rule_loads_with_lowercase_mvp_schema()
    {
        var service = new RuleJsonService(new TrustRuleValidator());

        var parsed = service.TryParse(MvpJsonRule(), out var rule, out var errors);

        Assert.That(parsed, Is.True, string.Join(" ", errors));
        Assert.That(rule!.Mode, Is.EqualTo(RuleMode.Watch));
        Assert.That(rule.Severity, Is.EqualTo(RuleSeverity.High));
        Assert.That(rule.Conditions.First().Operator, Is.EqualTo(RuleOperator.LessThan));
        Assert.That(rule.Actions.Last().Type, Is.EqualTo(RuleActionType.RouteToSafetyPage));
    }

    [Test]
    public void Invalid_json_rule_is_rejected()
    {
        var service = new RuleJsonService(new TrustRuleValidator());

        var parsed = service.TryParse("{ not json", out _, out var errors);

        Assert.That(parsed, Is.False);
        Assert.That(errors.Single(), Does.StartWith("Invalid JSON"));
    }

    [Test]
    public void Equals_operator_works()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active) with
        {
            Conditions = [new RuleCondition("url.usesShortener", RuleOperator.Equals, JsonSerializer.SerializeToElement(true))]
        };

        var result = new RuleMatchingEngine().Match(rule, new FactSet(new Dictionary<string, object?> { ["url.usesShortener"] = true }));

        Assert.That(result.IsMatch, Is.True);
    }

    [Test]
    public void LessThan_operator_works()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active) with
        {
            Conditions = [new RuleCondition("domain.ageDays", RuleOperator.LessThan, JsonSerializer.SerializeToElement(30))]
        };

        var result = new RuleMatchingEngine().Match(rule, new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 12 }));

        Assert.That(result.IsMatch, Is.True);
    }

    [Test]
    public void RuleConditionEvaluator_supports_text_operators_without_touching_match_loop()
    {
        var evaluator = new RuleConditionEvaluator();

        Assert.That(evaluator.IsMatch("secure-login.example", RuleOperator.Contains, JsonSerializer.SerializeToElement("LOGIN")), Is.True);
        Assert.That(evaluator.IsMatch("secure-login.example", RuleOperator.StartsWith, JsonSerializer.SerializeToElement("secure")), Is.True);
        Assert.That(evaluator.IsMatch("secure-login.example", RuleOperator.EndsWith, JsonSerializer.SerializeToElement(".example")), Is.True);
    }

    [Test]
    public void RuleConditionEvaluator_returns_false_for_unsupported_operator_values()
    {
        var evaluator = new RuleConditionEvaluator();

        var result = evaluator.IsMatch("anything", (RuleOperator)999, JsonSerializer.SerializeToElement("anything"));

        Assert.That(result, Is.False);
    }

    [Test]
    public void Disabled_rule_does_not_run()
    {
        var rule = NewDomainShortenerRule(RuleMode.Disabled) with { Enabled = false };
        var facts = new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 12, ["url.usesShortener"] = true });

        var result = new RuleMatchingEngine().Match(rule, facts);

        Assert.That(result.IsMatch, Is.False);
        Assert.That(result.FailedFields, Does.Contain("rule.disabled"));
    }

    [Test]
    public void Watch_rule_evaluates_but_does_not_enforce()
    {
        var rule = NewDomainShortenerRule(RuleMode.Watch);
        var service = EvaluationService();

        var result = service.Evaluate([rule], MatchingContext());

        Assert.That(result.MatchedRules, Does.Contain(rule.RuleId));
        Assert.That(result.WatchModeResults.Single().Enforced, Is.False);
        Assert.That(result.EnforcementResults, Is.Empty);
        Assert.That(result.ShouldRouteToSafetyPage, Is.False);
    }

    [Test]
    public void Active_rule_evaluates_and_enforces()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active);
        var service = EvaluationService();

        var result = service.Evaluate([rule], MatchingContext());

        Assert.That(result.MatchedRules, Does.Contain(rule.RuleId));
        Assert.That(result.EnforcementResults.Single().Enforced, Is.True);
        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.HighRisk));
    }

    [Test]
    public void Matched_rule_adds_plain_english_reason()
    {
        var result = EvaluationService().Evaluate([NewDomainShortenerRule(RuleMode.Active)], MatchingContext());

        Assert.That(result.Reasons.Single(), Does.Contain("shortened URL"));
    }

    [Test]
    public void RouteToSafetyPage_action_is_returned_when_matched()
    {
        var result = EvaluationService().Evaluate([NewDomainShortenerRule(RuleMode.Active)], MatchingContext());

        Assert.That(result.ShouldRouteToSafetyPage, Is.True);
        Assert.That(result.Actions.Select(action => action.Type), Does.Contain(RuleActionType.RouteToSafetyPage));
    }

    [Test]
    public void SetRiskLevel_accepts_high_alias()
    {
        var rule = NewDomainShortenerRule(RuleMode.Active) with
        {
            Actions = [new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement("High"))]
        };

        var result = new RuleActionApplier(new RuleMatchingEngine()).Apply(rule, new FactSet(new Dictionary<string, object?>
        {
            ["domain.ageDays"] = 12,
            ["url.usesShortener"] = true
        }));

        Assert.That(result.RiskLevel, Is.EqualTo(RiskStatus.HighRisk));
    }

    public static TrustRule NewDomainShortenerRule(RuleMode mode) => new(
        "new-domain-shortener-high-risk",
        "New Domain With Shortened URL",
        "Flags shortened links that resolve to new domains.",
        true,
        mode,
        RuleSeverity.HighRisk,
        [
            new RuleCondition("domain.ageDays", RuleOperator.LessThan, JsonSerializer.SerializeToElement(30)),
            new RuleCondition("url.usesShortener", RuleOperator.Equals, JsonSerializer.SerializeToElement(true))
        ],
        [
            new RuleAction(RuleActionType.SetRiskLevel, JsonSerializer.SerializeToElement("HighRisk")),
            new RuleAction(RuleActionType.AddScorePenalty, JsonSerializer.SerializeToElement(25)),
            new RuleAction(RuleActionType.AddReason, JsonSerializer.SerializeToElement("This link is risky because it uses a shortened URL that resolves to a new domain.")),
            new RuleAction(RuleActionType.RouteToSafetyPage, JsonSerializer.SerializeToElement(true))
        ],
        true,
        true,
        "system",
        "Detected repeated shortened links to new domains.",
        ApprovalStatus.Pending,
        0m,
        1);

    private static RuleEvaluationService EvaluationService()
    {
        var matching = new RuleMatchingEngine();
        return new RuleEvaluationService(matching, new RuleActionApplier(matching));
    }

    private static RuleScanContext MatchingContext() =>
        new(
            "https://bit.ly/example",
            "new-example.com",
            12,
            true,
            false,
            1,
            55,
            35,
            20);

    private static string MvpJsonRule() => """
        {
          "ruleId": "new-domain-shortener-high-risk",
          "name": "New Domain With Shortened URL",
          "description": "Flags shortened links that resolve to new domains.",
          "enabled": true,
          "mode": "watch",
          "severity": "high",
          "conditions": [
            { "field": "domain.ageDays", "operator": "lessThan", "value": 30 },
            { "field": "url.usesShortener", "operator": "equals", "value": true }
          ],
          "actions": [
            { "type": "setRiskLevel", "value": "High" },
            { "type": "addReason", "value": "This link is risky because it uses a shortener." },
            { "type": "routeToSafetyPage", "value": true }
          ],
          "requiresApproval": true,
          "simulationRequired": true,
          "createdBy": "admin",
          "createdReason": "MVP JSON rule",
          "approvalStatus": "pending",
          "confidenceScore": 0,
          "version": 1
        }
        """;
}
