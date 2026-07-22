using System.Text.Json;
using HIP.Application.Rules;
using HIP.Application.SiteSafety;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

/// <summary>Locks the HIP-0401 domain schema and legacy admin-contract mapping.</summary>
public sealed class HipRuleVersionSchemaTests
{
    private static readonly DateTimeOffset CreatedAt = new(2026, 7, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public void Version_schema_preserves_immutable_lifecycle_impact_approval_and_rollback_metadata()
    {
        var conditions = new[] { new HipRuleCondition("domain", "endsWith", "\".example\"") };
        var actions = new[] { new HipRuleAction("addWarning", "{\"code\":\"review\"}") };
        var approvals = new[] { new HipRuleApproval("approval:1", "approver:1", CreatedAt.AddMinutes(2)) };
        var version = Version(
            conditions: conditions,
            actions: actions,
            approvals: approvals,
            effectiveFromUtc: CreatedAt.AddMinutes(5));

        conditions[0] = new HipRuleCondition("changed", "equals", "true");
        actions[0] = new HipRuleAction("changed", "{}");
        approvals[0] = new HipRuleApproval("changed", "changed", CreatedAt);

        Assert.Multiple(() =>
        {
            Assert.That(version.SchemaVersion, Is.EqualTo("hip-rule/1"));
            Assert.That(version.VersionId, Is.EqualTo("rule:payment:v2"));
            Assert.That(version.PreviousVersionId, Is.EqualTo("rule:payment:v1"));
            Assert.That(version.ImpactLevel, Is.EqualTo(HipRuleImpactLevel.Medium));
            Assert.That(version.ApprovalRequirement, Is.EqualTo(HipRuleApprovalRequirement.OnePerson));
            Assert.That(version.Conditions.Single().Field, Is.EqualTo("domain"));
            Assert.That(version.Actions.Single().ActionType, Is.EqualTo("addWarning"));
            Assert.That(version.Approvals.Single().ApproverId, Is.EqualTo("approver:1"));
            Assert.That(version.Rollback.TargetVersionId, Is.EqualTo("rule:payment:v1"));
        });
    }

    [Test]
    public void Schema_rejects_policy_lineage_time_and_independent_approval_violations()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => Version(approvalRequirement: HipRuleApprovalRequirement.TwoPerson),
                Throws.ArgumentException.With.Message.Contains("approval policy"));
            Assert.That(
                () => Version(version: 2, previousVersionId: null),
                Throws.ArgumentException.With.Message.Contains("lineage"));
            Assert.That(
                () => Version(effectiveFromUtc: CreatedAt.AddMinutes(-1)),
                Throws.ArgumentException.With.Message.Contains("out of order"));
            Assert.That(
                () => Version(approvals: [new HipRuleApproval("approval:creator", "CREATOR:1", CreatedAt.AddMinutes(1))]),
                Throws.ArgumentException.With.Message.Contains("independent"));
            Assert.That(
                () => Version(approvals:
                [
                    new HipRuleApproval("approval:1", "approver:1", CreatedAt.AddMinutes(1)),
                    new HipRuleApproval("approval:2", "approver:1", CreatedAt.AddMinutes(2))
                ]),
                Throws.ArgumentException.With.Message.Contains("unique"));
        });
    }

    [Test]
    public void Active_rule_requires_effective_time_and_exactly_one_rollback_target()
    {
        Assert.Multiple(() =>
        {
            Assert.That(
                () => Version(includeEffectiveTime: false),
                Throws.ArgumentException.With.Message.Contains("effective time"));
            Assert.That(
                () => Version(rollback: new HipRuleRollback(null, false, false, null, null)),
                Throws.ArgumentException.With.Message.Contains("one target"));
            Assert.That(
                () => Version(rollback: new HipRuleRollback("rule:payment:v1", true, false, null, null)),
                Throws.ArgumentException.With.Message.Contains("one target"));
            Assert.That(
                () => Version(conditions: [new HipRuleCondition("domain", "equals", "not-json")]),
                Throws.ArgumentException.With.Message.Contains("JSON"));
        });
    }

    [Test]
    public void Version_schema_round_trips_through_json_without_mutable_collection_loss()
    {
        var original = Version();

        var json = JsonSerializer.Serialize(original);
        var restored = JsonSerializer.Deserialize<HipRuleVersion>(json);

        Assert.Multiple(() =>
        {
            Assert.That(restored, Is.Not.Null);
            Assert.That(restored!.VersionId, Is.EqualTo(original.VersionId));
            Assert.That(restored.Conditions, Is.EqualTo(original.Conditions));
            Assert.That(restored.Actions, Is.EqualTo(original.Actions));
            Assert.That(restored.Approvals, Is.EqualTo(original.Approvals));
            Assert.That(restored.Rollback, Is.EqualTo(original.Rollback));
        });
    }

    [Test]
    public void Existing_admin_contract_maps_additively_without_losing_conditions_or_effects()
    {
        var adminRule = new AdminSiteSafetyRule(
            RuleId: "payment-review",
            Name: "Payment review",
            Description: "Review payment forms.",
            TargetType: AdminSiteSafetyRuleTargetType.PageContent,
            Conditions:
            [
                new AdminSiteSafetyRuleCondition(
                    "HasPaymentField",
                    AdminSiteSafetyRuleOperator.Equals,
                    JsonSerializer.SerializeToElement(true))
            ],
            Effects: new AdminSiteSafetyRuleEffects(
                IncreaseFormRisk: 40,
                AddWarning: "Review this payment form."),
            Severity: SiteSafetyRuleSeverity.Medium,
            EvidenceQuality: SiteSafetyEvidenceQuality.Strong,
            Status: AdminSiteSafetyRuleStatus.Active,
            Mode: AdminSiteSafetyRuleMode.Enforced,
            CreatedBy: "creator:1",
            CreatedAtUtc: CreatedAt,
            ApprovedBy: "approver:1",
            ApprovedAtUtc: CreatedAt.AddMinutes(2),
            Version: 1,
            PreviousVersionId: null,
            IsRollbackAvailable: false);

        var mapped = AdminSiteSafetyRuleVersionMapper.ToDomainVersion(adminRule);

        Assert.Multiple(() =>
        {
            Assert.That(mapped.RuleId, Is.EqualTo(adminRule.RuleId));
            Assert.That(mapped.Status, Is.EqualTo(HipRuleStatus.Active));
            Assert.That(mapped.Mode, Is.EqualTo(HipRuleMode.Active));
            Assert.That(mapped.Conditions.Single().Operator, Is.EqualTo("equals"));
            Assert.That(mapped.Conditions.Single().ExpectedValueJson, Is.EqualTo("true"));
            Assert.That(mapped.Actions.Single().ParametersJson, Does.Contain("Review this payment form."));
            Assert.That(mapped.EffectiveFromUtc, Is.EqualTo(adminRule.ApprovedAtUtc));
            Assert.That(mapped.Rollback.UseDisabledFallback, Is.True);
        });
    }

    private static HipRuleVersion Version(
        int version = 2,
        string? previousVersionId = "rule:payment:v1",
        HipRuleApprovalRequirement approvalRequirement = HipRuleApprovalRequirement.OnePerson,
        IReadOnlyCollection<HipRuleCondition>? conditions = null,
        IReadOnlyCollection<HipRuleAction>? actions = null,
        IReadOnlyCollection<HipRuleApproval>? approvals = null,
        DateTimeOffset? effectiveFromUtc = default,
        bool includeEffectiveTime = true,
        HipRuleRollback? rollback = null) =>
        new(
            HipRuleVersion.CurrentSchemaVersion,
            "rule:payment",
            $"rule:payment:v{version}",
            version,
            "Payment review",
            "Reviews privacy-safe payment-form signals.",
            HipRuleStatus.Active,
            HipRuleMode.Active,
            HipRuleImpactLevel.Medium,
            HipRuleCreatorType.Human,
            "creator:1",
            CreatedAt,
            conditions ?? [new HipRuleCondition("domain", "endsWith", "\".example\"")],
            actions ?? [new HipRuleAction("addWarning", "{\"code\":\"review\"}")],
            simulationRequired: true,
            approvalRequirement,
            approvals ?? [new HipRuleApproval("approval:1", "approver:1", CreatedAt.AddMinutes(2))],
            includeEffectiveTime
                ? effectiveFromUtc == default ? CreatedAt.AddMinutes(5) : effectiveFromUtc
                : null,
            expiresAtUtc: CreatedAt.AddDays(30),
            previousVersionId,
            rollback ?? new HipRuleRollback(previousVersionId, previousVersionId is null, false, null, null));
}
