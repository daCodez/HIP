using System.Text.Json;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class RuleBuilderFormModel
{
    public static readonly RuleMode[] SupportedModes = [RuleMode.Watch, RuleMode.Active, RuleMode.Disabled];
    public static readonly RuleSeverity[] MvpSeverities = [RuleSeverity.Low, RuleSeverity.Medium, RuleSeverity.High, RuleSeverity.Critical];
    public static readonly RuleActionType[] MvpActions =
    [
        RuleActionType.SetRiskLevel,
        RuleActionType.AddReason,
        RuleActionType.RouteToSafetyPage,
        RuleActionType.Block,
        RuleActionType.Allow,
        RuleActionType.RequireReview
    ];

    public string RuleId { get; set; } = "new-domain-shortener-high-risk";
    public string Name { get; set; } = "New Domain With Shortened URL";
    public string Description { get; set; } = "Flags shortened links that resolve to new domains.";
    public bool Enabled { get; set; } = true;
    public RuleMode Mode { get; set; } = RuleMode.Watch;
    public RuleSeverity Severity { get; set; } = RuleSeverity.High;
    public List<RuleConditionInput> Conditions { get; } = [];
    public List<RuleActionInput> Actions { get; } = [];
    public bool RequiresApproval { get; set; } = true;
    public bool SimulationRequired { get; set; } = true;
    public string CreatedBy { get; set; } = "admin";
    public string CreatedReason { get; set; } = "Suspicious shortened URL pattern";
    public decimal ConfidenceScore { get; set; }
    public int Version { get; set; } = 1;

    public static RuleBuilderFormModel Default()
    {
        var form = new RuleBuilderFormModel();
        form.Conditions.Add(new RuleConditionInput { Field = "domain.ageDays", Operator = RuleOperator.LessThan, Value = "30" });
        form.Conditions.Add(new RuleConditionInput { Field = "url.usesShortener", Operator = RuleOperator.Equals, Value = "true" });
        form.Actions.Add(new RuleActionInput { Type = RuleActionType.SetRiskLevel, Value = "High" });
        form.Actions.Add(new RuleActionInput { Type = RuleActionType.AddReason, Value = "This link is risky because it uses a shortener." });
        form.Actions.Add(new RuleActionInput { Type = RuleActionType.RouteToSafetyPage, Value = "true" });
        return form;
    }

    public TrustRule ToRule() => new(
        RuleId,
        Name,
        Description,
        Enabled,
        Mode,
        Severity,
        Conditions.Select(condition => new RuleCondition(condition.Field, condition.Operator, ToJsonElement(condition.Value))).ToArray(),
        Actions.Select(action => new RuleAction(action.Type, ToJsonElement(action.Value))).ToArray(),
        RequiresApproval,
        SimulationRequired,
        CreatedBy,
        CreatedReason,
        RequiresApproval ? ApprovalStatus.Pending : ApprovalStatus.NotRequired,
        ConfidenceScore,
        Version);

    public void Load(TrustRule rule)
    {
        RuleId = rule.RuleId;
        Name = rule.Name;
        Description = rule.Description;
        Enabled = rule.Enabled;
        Mode = rule.Mode;
        Severity = rule.Severity;
        Conditions.Clear();
        Conditions.AddRange(rule.Conditions.Select(condition => new RuleConditionInput
        {
            Field = condition.Field,
            Operator = condition.Operator,
            Value = JsonValueText(condition.Value)
        }));
        Actions.Clear();
        Actions.AddRange(rule.Actions.Select(action => new RuleActionInput
        {
            Type = action.Type,
            Value = JsonValueText(action.Value)
        }));
        RequiresApproval = rule.RequiresApproval;
        SimulationRequired = rule.SimulationRequired;
        CreatedBy = rule.CreatedBy;
        CreatedReason = rule.CreatedReason;
        ConfidenceScore = rule.ConfidenceScore;
        Version = rule.Version;
    }

    public static JsonElement ToJsonElement(string value)
    {
        if (bool.TryParse(value, out var boolean))
        {
            return JsonSerializer.SerializeToElement(boolean);
        }

        if (decimal.TryParse(value, out var number))
        {
            return JsonSerializer.SerializeToElement(number);
        }

        return JsonSerializer.SerializeToElement(value);
    }

    private static string JsonValueText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.True => bool.TrueString.ToLowerInvariant(),
        JsonValueKind.False => bool.FalseString.ToLowerInvariant(),
        JsonValueKind.Number => value.GetRawText(),
        _ => value.ToString()
    };
}

public sealed class RuleConditionInput
{
    public string Field { get; set; } = "domain.ageDays";
    public RuleOperator Operator { get; set; } = RuleOperator.LessThan;
    public string Value { get; set; } = "30";
}

public sealed class RuleActionInput
{
    public RuleActionType Type { get; set; } = RuleActionType.SetRiskLevel;
    public string Value { get; set; } = "High";
}
