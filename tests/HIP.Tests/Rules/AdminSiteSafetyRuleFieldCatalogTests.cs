using System.Text.Json;
using FluentValidation;
using HIP.Application.Rules;
using HIP.Application.SiteSafety;

namespace HIP.Tests.Rules;

/// <summary>Adversarial HIP-0402 field, operator, JSON-value, and canonical-name tests.</summary>
public sealed class AdminSiteSafetyRuleFieldCatalogTests
{
    [Test]
    public void Catalog_is_immutable_and_excludes_private_content_fields()
    {
        var fields = (IList<AdminSiteSafetyRuleFieldDefinition>)AdminSiteSafetyRuleFieldCatalog.Fields;

        Assert.Multiple(() =>
        {
            Assert.That(fields, Has.Count.EqualTo(20));
            Assert.That(fields.Select(field => field.Name), Does.Contain("Domain"));
            Assert.That(fields.Select(field => field.Name), Does.Not.Contain("PageText"));
            Assert.That(fields.Select(field => field.Name), Does.Not.Contain("Password"));
            Assert.That(
                () => fields[0] = new("Unsafe", AdminSiteSafetyRuleFieldValueType.String, []),
                Throws.TypeOf<NotSupportedException>());
        });
    }

    [TestCase("HasHttps", AdminSiteSafetyRuleOperator.GreaterThan, "true")]
    [TestCase("RedirectCount", AdminSiteSafetyRuleOperator.Contains, "\"1\"")]
    [TestCase("Domain", AdminSiteSafetyRuleOperator.Equals, "42")]
    [TestCase("MatchedRiskTerms", AdminSiteSafetyRuleOperator.ContainsAny, "\"phishing\"")]
    [TestCase("UnknownField", AdminSiteSafetyRuleOperator.Equals, "\"value\"")]
    public void Validator_rejects_unsupported_fields_operators_and_value_types(
        string field,
        AdminSiteSafetyRuleOperator ruleOperator,
        string valueJson)
    {
        var rule = Rule(new AdminSiteSafetyRuleCondition(
            field,
            ruleOperator,
            JsonDocument.Parse(valueJson).RootElement.Clone()));

        Assert.ThrowsAsync<ValidationException>(() =>
            new AdminSiteSafetyRuleValidator().ValidateAndThrowAsync(rule, CancellationToken.None));
    }

    [Test]
    public void Catalog_rejects_null_empty_oversized_and_mixed_lists()
    {
        var oversized = Enumerable.Range(0, 65).Select(index => $"value-{index}").ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(Valid("Domain", AdminSiteSafetyRuleOperator.Equals, "null"), Is.False);
            Assert.That(Valid("Domain", AdminSiteSafetyRuleOperator.InList, "[]"), Is.False);
            Assert.That(Valid(
                "Domain",
                AdminSiteSafetyRuleOperator.InList,
                JsonSerializer.Serialize(oversized)), Is.False);
            Assert.That(Valid("RedirectCount", AdminSiteSafetyRuleOperator.InList, "[1,\"2\"]"), Is.False);
        });
    }

    [Test]
    public void Valid_typed_conditions_map_and_evaluate_with_canonical_case()
    {
        var condition = new AdminSiteSafetyRuleCondition(
            "domain",
            AdminSiteSafetyRuleOperator.EndsWith,
            JsonSerializer.SerializeToElement(".example"));
        var rule = Rule(condition);
        var input = new SiteSafetyRuleInput(
            new Uri("https://typed.example"),
            "typed.example",
            "example",
            true,
            0, 0, 0, false, 0, 0, 0, 0, 0,
            false, false, false, 0, null, null, [], [], true);

        var validation = new AdminSiteSafetyRuleValidator().Validate(rule);
        var mapped = AdminSiteSafetyRuleVersionMapper.ToDomainVersion(rule);

        Assert.Multiple(() =>
        {
            Assert.That(validation.IsValid, Is.True);
            Assert.That(AdminSiteSafetyRuleConditionEvaluator.Matches(condition, input), Is.True);
            Assert.That(mapped.Conditions.Single().Field, Is.EqualTo("Domain"));
            Assert.That(mapped.Conditions.Single().Operator, Is.EqualTo("endsWith"));
        });
    }

    private static bool Valid(string field, AdminSiteSafetyRuleOperator ruleOperator, string json)
    {
        var condition = new AdminSiteSafetyRuleCondition(
            field,
            ruleOperator,
            JsonDocument.Parse(json).RootElement.Clone());
        return AdminSiteSafetyRuleFieldCatalog.TryValidate(condition, out _);
    }

    private static AdminSiteSafetyRule Rule(AdminSiteSafetyRuleCondition condition) =>
        new(
            "typed-rule",
            "Typed rule",
            "HIP-0402 typed condition test.",
            AdminSiteSafetyRuleTargetType.PageContent,
            [condition],
            new AdminSiteSafetyRuleEffects(AddWarning: "Typed rule matched."),
            SiteSafetyRuleSeverity.Medium,
            SiteSafetyEvidenceQuality.Medium,
            AdminSiteSafetyRuleStatus.Draft,
            AdminSiteSafetyRuleMode.Simulation,
            "creator:1",
            new DateTimeOffset(2026, 7, 20, 0, 0, 0, TimeSpan.Zero),
            null,
            null,
            1,
            null,
            false);
}
