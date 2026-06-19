using System.Text.Json;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

public sealed class AdminRuleBuilderTests
{
    /// <summary>
    /// Confirms the rule builder exposes only the MVP modes, severities, and safe structured actions.
    /// </summary>
    [Test]
    public void Rule_builder_supported_choices_match_mvp_surface()
    {
        Assert.That(RuleBuilderFormModel.SupportedModes, Is.EqualTo(new[] { RuleMode.Watch, RuleMode.Active, RuleMode.Disabled }));
        Assert.That(RuleBuilderFormModel.MvpSeverities, Does.Contain(RuleSeverity.Critical));
        Assert.That(RuleBuilderFormModel.MvpActions, Does.Contain(RuleActionType.RouteToSafetyPage));
        Assert.That(RuleBuilderFormModel.MvpActions, Does.Not.Contain(RuleActionType.MarkForSimulation));
    }

    /// <summary>
    /// Confirms loading an existing rule preserves editable values and turns JSON values back into form text.
    /// </summary>
    [Test]
    public void Rule_builder_load_round_trips_existing_rule_into_form_fields()
    {
        var original = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            RuleId = "round-trip-rule",
            Name = "Round Trip Rule",
            Description = "Preserves editable rule fields.",
            Enabled = false,
            RequiresApproval = false,
            SimulationRequired = false,
            CreatedBy = "admin@example.test",
            CreatedReason = "Regression coverage",
            ConfidenceScore = 87.5m,
            Version = 7
        };
        var form = new RuleBuilderFormModel();

        form.Load(original);

        Assert.That(form.RuleId, Is.EqualTo("round-trip-rule"));
        Assert.That(form.Name, Is.EqualTo("Round Trip Rule"));
        Assert.That(form.Enabled, Is.False);
        Assert.That(form.Mode, Is.EqualTo(RuleMode.Active));
        Assert.That(form.RequiresApproval, Is.False);
        Assert.That(form.SimulationRequired, Is.False);
        Assert.That(form.CreatedBy, Is.EqualTo("admin@example.test"));
        Assert.That(form.CreatedReason, Is.EqualTo("Regression coverage"));
        Assert.That(form.ConfidenceScore, Is.EqualTo(87.5m));
        Assert.That(form.Version, Is.EqualTo(7));
        Assert.That(form.Conditions.Select(condition => condition.Value), Does.Contain("30"));
        Assert.That(form.Conditions.Select(condition => condition.Value), Does.Contain("true"));
        Assert.That(form.Actions.Select(action => action.Value), Does.Contain("HighRisk"));
    }

    /// <summary>
    /// Confirms form values become typed JSON so rules compare numbers and booleans correctly.
    /// </summary>
    [Test]
    public void Rule_builder_converts_form_values_to_typed_json()
    {
        var boolean = RuleBuilderFormModel.ToJsonElement("true");
        var number = RuleBuilderFormModel.ToJsonElement("42.5");
        var text = RuleBuilderFormModel.ToJsonElement("High");

        Assert.That(boolean.ValueKind, Is.EqualTo(JsonValueKind.True));
        Assert.That(number.ValueKind, Is.EqualTo(JsonValueKind.Number));
        Assert.That(number.GetDecimal(), Is.EqualTo(42.5m));
        Assert.That(text.ValueKind, Is.EqualTo(JsonValueKind.String));
        Assert.That(text.GetString(), Is.EqualTo("High"));
    }

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
    public void Rule_builder_form_generates_valid_json()
    {
        var service = JsonService();
        var form = RuleBuilderFormModel.Default();
        var json = service.ToJson(form.ToRule());

        var parsed = service.TryParse(json, out var rule, out var errors);

        Assert.That(parsed, Is.True, string.Join(" ", errors));
        Assert.That(rule!.Name, Is.EqualTo(form.Name));
    }

    [Test]
    public void Json_preview_includes_conditions()
    {
        var json = JsonService().ToJson(RuleBuilderFormModel.Default().ToRule());

        Assert.That(json, Does.Contain("\"conditions\""));
        Assert.That(json, Does.Contain("domain.ageDays"));
        Assert.That(json, Does.Contain("url.usesShortener"));
    }

    [Test]
    public void Json_preview_includes_actions()
    {
        var json = JsonService().ToJson(RuleBuilderFormModel.Default().ToRule());

        Assert.That(json, Does.Contain("\"actions\""));
        Assert.That(json, Does.Contain("setRiskLevel"));
        Assert.That(json, Does.Contain("routeToSafetyPage"));
    }

    [Test]
    public void Save_rejects_unsupported_operator()
    {
        var service = JsonService();
        var json = RuleJson().Replace("\"LessThan\"", "\"UnsupportedOperator\"");

        var parsed = service.TryParse(json, out _, out var errors);

        Assert.That(parsed, Is.False);
        Assert.That(errors, Does.Contain("Unsupported operator."));
    }

    [Test]
    public void Run_simulation_returns_mvp_summary()
    {
        var service = AdminService();

        var result = service.Simulate(RuleBuilderFormModel.Default().ToRule(), null);

        Assert.That(result.TotalTestCases, Is.GreaterThan(0));
        Assert.That(result.RecommendedAction, Is.Not.Empty);
        Assert.That(result.RecommendedMode, Is.Not.Empty);
        Assert.That(result.FalsePositiveRisk, Is.InRange(0m, 1m));
        Assert.That(result.FalseNegativeRisk, Is.InRange(0m, 1m));
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
        return new AdminRuleService(new TrustRuleValidator(), new InMemoryRuleRepository(), new RuleSimulationService(applier), new HIP.Application.Review.AuditLogService(new HIP.Application.Review.InMemoryAuditLogRepository()));
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
