using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Tests.Rules;

namespace HIP.Tests.Simulation;

public sealed class RuleSimulationServiceTests
{
    [Test]
    public void Simulate_calculates_confidence_from_case_results()
    {
        var service = new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine()));
        var rule = RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active);

        var result = service.Simulate(rule, [
            new RuleSimulationTestCase(
                "shortener to new domain",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 10, ["url.usesShortener"] = true }),
                true,
                RiskStatus.HighRisk,
                true),
            new RuleSimulationTestCase(
                "old direct domain",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false }),
                false,
                null,
                null)
        ]);

        Assert.That(result.Passed, Is.True);
        Assert.That(result.TotalTestCases, Is.EqualTo(2));
        Assert.That(result.ConfidenceScore, Is.LessThan(1m));
        Assert.That(result.ConfidenceScore, Is.GreaterThan(0.8m));
        Assert.That(result.FalsePositiveRisk, Is.EqualTo(0m));
        Assert.That(result.FalseNegativeRisk, Is.EqualTo(0m));
    }

    [Test]
    public void Simulation_runs_against_seed_cases()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), null);

        Assert.That(result.TotalTestCases, Is.GreaterThanOrEqualTo(10));
        Assert.That(result.PrivacyImpact, Does.Contain("no private content"));
    }

    [Test]
    public void Known_bad_case_is_detected()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), [
            new RuleSimulationTestCase(
                "known bad shortener",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 5, ["url.usesShortener"] = true }),
                true,
                RiskStatus.HighRisk,
                true)
        ]);

        Assert.That(result.Passed, Is.True);
        Assert.That(result.MatchedRules, Does.Contain("new-domain-shortener-high-risk"));
    }

    [Test]
    public void Known_safe_case_is_not_flagged()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), [
            new RuleSimulationTestCase(
                "known safe link",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false }),
                false,
                null,
                null)
        ]);

        Assert.That(result.Passed, Is.True);
        Assert.That(result.FalsePositiveRisk, Is.EqualTo(0m));
    }

    [Test]
    public void False_positive_affects_confidence_score()
    {
        var broadRule = RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active) with
        {
            Conditions = [new HIP.Domain.Rules.RuleCondition("domain.ageDays", HIP.Domain.Rules.RuleOperator.GreaterThan, System.Text.Json.JsonSerializer.SerializeToElement(1))]
        };

        var result = Service().Simulate(broadRule, [
            new RuleSimulationTestCase("safe old domain", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false }), false, null, null)
        ]);

        Assert.That(result.Passed, Is.False);
        Assert.That(result.FalsePositiveRisk, Is.EqualTo(1m));
        Assert.That(result.ConfidenceScore, Is.LessThan(0.8m));
    }

    [Test]
    public void False_negative_affects_confidence_score()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), [
            new RuleSimulationTestCase("missed bad case", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = true }), true, RiskStatus.HighRisk, true)
        ]);

        Assert.That(result.Passed, Is.False);
        Assert.That(result.FalseNegativeRisk, Is.EqualTo(1m));
        Assert.That(result.ConfidenceScore, Is.LessThan(0.8m));
    }

    [Test]
    public void High_impact_rule_recommends_watch_mode()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), [
            new RuleSimulationTestCase("bad", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 5, ["url.usesShortener"] = true }), true, RiskStatus.HighRisk, true),
            new RuleSimulationTestCase("safe", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false }), false, null, null)
        ]);

        Assert.That(result.ImpactClassification, Is.EqualTo("high impact"));
        Assert.That(result.RecommendedMode, Is.EqualTo("watch"));
    }

    [Test]
    public void Failed_simulation_does_not_recommend_auto_enable()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), [
            new RuleSimulationTestCase("safe old domain", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 10, ["url.usesShortener"] = true }), false, null, null)
        ]);

        Assert.That(result.Passed, Is.False);
        Assert.That(result.RecommendedAction, Does.Contain("Do not auto-enable"));
    }

    [Test]
    public void Simulation_output_includes_plain_english_recommendation()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), null);

        Assert.That(result.RecommendedAction, Is.Not.Empty);
        Assert.That(result.RecommendedAction, Does.Contain("watch").Or.Contain("Review").Or.Contain("approval"));
    }

    [Test]
    public void Simulation_result_does_not_expose_private_data()
    {
        var result = Service().Simulate(RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active), null);
        var names = result.CaseResults.Select(item => item.Name).ToArray();

        Assert.That(names, Does.Not.Contain("private chat log"));
        Assert.That(result.PrivacyImpact, Does.Not.Contain("message body"));
    }

    private static RuleSimulationService Service() =>
        new(new RuleActionApplier(new RuleMatchingEngine()));
}
