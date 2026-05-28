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
}
