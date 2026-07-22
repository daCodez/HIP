using System.Text.Json;
using HIP.Application.SiteSafety;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>Maps the compatibility-sensitive admin rule contract into the HIP-0401 domain schema.</summary>
public static class AdminSiteSafetyRuleVersionMapper
{
    public static HipRuleVersion ToDomainVersion(AdminSiteSafetyRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule.Conditions.Any(condition =>
                !AdminSiteSafetyRuleFieldCatalog.TryValidate(condition, out _)))
        {
            throw new ArgumentException("Admin rule conditions do not match the typed HIP rule catalog.", nameof(rule));
        }
        var impact = (HipRuleImpactLevel)(int)rule.Severity;
        var approvalRequirement = impact switch
        {
            HipRuleImpactLevel.Low => HipRuleApprovalRequirement.None,
            HipRuleImpactLevel.Medium => HipRuleApprovalRequirement.OnePerson,
            HipRuleImpactLevel.High => HipRuleApprovalRequirement.TwoPerson,
            HipRuleImpactLevel.Critical => HipRuleApprovalRequirement.ManualTwoPerson,
            _ => throw new ArgumentOutOfRangeException(nameof(rule))
        };
        var approvals = rule.ApprovedBy is null || rule.ApprovedAtUtc is null
            ? Array.Empty<HipRuleApproval>()
            : [new HipRuleApproval(
                $"legacy-approval:{rule.RuleId}:v{rule.Version}",
                rule.ApprovedBy,
                rule.ApprovedAtUtc.Value)];
        DateTimeOffset? effectiveFrom = rule.Status is AdminSiteSafetyRuleStatus.Active
            ? rule.UpdatedAtUtc ?? rule.ApprovedAtUtc ?? rule.CreatedAtUtc
            : null;

        return new HipRuleVersion(
            HipRuleVersion.CurrentSchemaVersion,
            rule.RuleId,
            $"{rule.RuleId}:v{rule.Version}",
            rule.Version,
            rule.Name,
            rule.Description,
            MapStatus(rule.Status),
            MapMode(rule.Status, rule.Mode),
            impact,
            HipRuleCreatorType.Human,
            rule.CreatedBy,
            rule.CreatedAtUtc,
            rule.Conditions.Select(MapCondition).ToArray(),
            [new HipRuleAction("legacy-site-safety-effects", JsonSerializer.Serialize(rule.Effects))],
            simulationRequired: true,
            approvalRequirement,
            approvals,
            effectiveFrom,
            expiresAtUtc: null,
            rule.PreviousVersionId,
            new HipRuleRollback(
                rule.IsRollbackAvailable ? rule.PreviousVersionId : null,
                UseDisabledFallback: !rule.IsRollbackAvailable,
                TestRequired: impact is HipRuleImpactLevel.Critical,
                TestedAtUtc: null,
                TestedBy: null));
    }

    private static HipRuleCondition MapCondition(AdminSiteSafetyRuleCondition condition)
    {
        if (!AdminSiteSafetyRuleFieldCatalog.TryGet(condition.Field, out var definition))
        {
            throw new ArgumentException("Admin rule condition field is not in the typed HIP rule catalog.", nameof(condition));
        }

        return new HipRuleCondition(
            definition.Name,
            OperatorName(condition.Operator),
            condition.Value.GetRawText());
    }

    private static HipRuleStatus MapStatus(AdminSiteSafetyRuleStatus status) => status switch
    {
        AdminSiteSafetyRuleStatus.Draft => HipRuleStatus.Draft,
        AdminSiteSafetyRuleStatus.PendingApproval => HipRuleStatus.PendingApproval,
        AdminSiteSafetyRuleStatus.Approved => HipRuleStatus.Approved,
        AdminSiteSafetyRuleStatus.Active => HipRuleStatus.Active,
        AdminSiteSafetyRuleStatus.Disabled => HipRuleStatus.Disabled,
        AdminSiteSafetyRuleStatus.Archived => HipRuleStatus.Archived,
        _ => throw new ArgumentOutOfRangeException(nameof(status))
    };

    private static HipRuleMode MapMode(AdminSiteSafetyRuleStatus status, AdminSiteSafetyRuleMode mode) =>
        status is AdminSiteSafetyRuleStatus.Disabled or AdminSiteSafetyRuleStatus.Archived
            ? HipRuleMode.Disabled
            : mode switch
            {
                AdminSiteSafetyRuleMode.Simulation => HipRuleMode.Disabled,
                AdminSiteSafetyRuleMode.WatchOnly => HipRuleMode.Watch,
                AdminSiteSafetyRuleMode.Enforced => HipRuleMode.Active,
                _ => throw new ArgumentOutOfRangeException(nameof(mode))
            };

    private static string OperatorName(AdminSiteSafetyRuleOperator value) => value switch
    {
        AdminSiteSafetyRuleOperator.Equals => "equals",
        AdminSiteSafetyRuleOperator.NotEquals => "notEquals",
        AdminSiteSafetyRuleOperator.GreaterThan => "greaterThan",
        AdminSiteSafetyRuleOperator.GreaterThanOrEqual => "greaterThanOrEqual",
        AdminSiteSafetyRuleOperator.LessThan => "lessThan",
        AdminSiteSafetyRuleOperator.LessThanOrEqual => "lessThanOrEqual",
        AdminSiteSafetyRuleOperator.Contains => "contains",
        AdminSiteSafetyRuleOperator.ContainsAny => "containsAny",
        AdminSiteSafetyRuleOperator.StartsWith => "startsWith",
        AdminSiteSafetyRuleOperator.EndsWith => "endsWith",
        AdminSiteSafetyRuleOperator.InList => "in",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };
}
