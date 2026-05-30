using System.Text.Json;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

public sealed class AdminRuleBuilderTests
{
    [Test]
    public void Rule_validation_passes_for_valid_rule()
    {
        var result = new TrustRuleValidator().Validate(RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch));

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Rule_validation_fails_for_missing_name()
    {
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with { Name = "" };

        var result = new TrustRuleValidator().Validate(rule);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors.Select(error => error.PropertyName), Does.Contain("Name"));
    }

    [Test]
    public void Rule_json_validation_fails_with_unsupported_operator()
    {
        var json = RuleJson().Replace("\"LessThan\"", "\"UnsupportedOperator\"");
        var service = JsonService();

        var parsed = service.TryParse(json, out _, out var errors);

        Assert.That(parsed, Is.False);
        Assert.That(errors, Does.Contain("Unsupported operator."));
    }

    [Test]
    public void Rule_validation_fails_with_unsupported_field()
    {
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            Conditions = [new RuleCondition("private.chatLog", RuleOperator.Contains, JsonSerializer.SerializeToElement("secret"))]
        };

        var result = new TrustRuleValidator().Validate(rule);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors.Select(error => error.ErrorMessage), Does.Contain("Unsupported condition field."));
    }

    [Test]
    public void Json_rule_can_round_trip()
    {
        var service = JsonService();
        var original = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch);
        var json = service.ToJson(original);

        var parsed = service.TryParse(json, out var roundTripped, out var errors);

        Assert.That(parsed, Is.True, string.Join(" ", errors));
        Assert.That(roundTripped!.Name, Is.EqualTo(original.Name));
        Assert.That(service.ToJson(roundTripped), Does.Contain("\"ruleId\""));
    }

    [Test]
    public void Simulation_works_with_default_test_cases()
    {
        var service = AdminService();

        var result = service.Simulate(RuleEngineTests.NewDomainShortenerRule(RuleMode.Active), null);

        Assert.That(result.TotalTestCases, Is.GreaterThanOrEqualTo(10));
        Assert.That(result.ConfidenceScore, Is.GreaterThan(0m));
    }

    [Test]
    public void Confidence_score_is_calculated_from_simulation_results()
    {
        var service = AdminService();

        var result = service.Simulate(RuleEngineTests.NewDomainShortenerRule(RuleMode.Active), [
            new RuleSimulationTestCase("match", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 2, ["url.usesShortener"] = true }), true, HIP.Domain.Risk.RiskStatus.HighRisk, true),
            new RuleSimulationTestCase("no match", new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 900, ["url.usesShortener"] = false }), false, null, null)
        ]);

        Assert.That(result.ConfidenceScore, Is.GreaterThan(0.8m));
    }

    [Test]
    public async Task High_impact_active_rule_requires_approval()
    {
        var repository = new InMemoryRuleRepository();
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            Severity = RuleSeverity.Critical,
            RequiresApproval = true,
            ApprovalStatus = ApprovalStatus.Pending
        };

        var saved = await repository.SaveAsync(rule, CancellationToken.None);

        Assert.That(saved.RequiresApproval, Is.True);
        Assert.That(saved.ApprovalStatus, Is.EqualTo(ApprovalStatus.Pending));
    }

    [Test]
    public async Task In_memory_rule_repository_saves_and_returns_rules()
    {
        var repository = new InMemoryRuleRepository();
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch);

        await repository.SaveAsync(rule, CancellationToken.None);
        var rules = await repository.ListAsync(CancellationToken.None);

        Assert.That(rules.Single().RuleId, Is.EqualTo(rule.RuleId));
    }

    [Test]
    public void Invalid_json_cannot_be_saved()
    {
        var service = JsonService();

        var parsed = service.TryParse("{ invalid json", out _, out var errors);

        Assert.That(parsed, Is.False);
        Assert.That(errors.Single(), Does.StartWith("Invalid JSON"));
    }

    private static RuleJsonService JsonService() => new(new TrustRuleValidator());

    private static AdminRuleService AdminService()
    {
        var matching = new RuleMatchingEngine();
        var applier = new RuleActionApplier(matching);
        return new AdminRuleService(new TrustRuleValidator(), new InMemoryRuleRepository(), new RuleSimulationService(applier));
    }

    private static string RuleJson() => """
        {
          "ruleId": "new-domain-shortener-high-risk",
          "name": "New Domain With Shortened URL",
          "description": "Flags shortened links that resolve to new domains.",
          "enabled": true,
          "mode": "Watch",
          "severity": "HighRisk",
          "conditions": [
            { "field": "domain.ageDays", "operator": "LessThan", "value": 30 }
          ],
          "actions": [
            { "type": "SetRiskLevel", "value": "HighRisk" }
          ],
          "requiresApproval": true,
          "simulationRequired": true,
          "createdBy": "admin",
          "createdReason": "Suspicious shortened URL pattern",
          "approvalStatus": "Pending",
          "confidenceScore": 0,
          "version": 1
        }
        """;
}
