using System.Text.Json;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>
/// Holds the simple admin rule-builder form state and converts it to a structured HIP rule.
/// </summary>
public sealed class RuleBuilderFormModel
{
    /// <summary>
    /// Rule modes that the MVP form allows admins to choose from.
    /// </summary>
    public static readonly RuleMode[] SupportedModes = [RuleMode.Watch, RuleMode.Active, RuleMode.Disabled];

    /// <summary>
    /// Severity values exposed in the MVP rule builder.
    /// </summary>
    public static readonly RuleSeverity[] MvpSeverities = [RuleSeverity.Low, RuleSeverity.Medium, RuleSeverity.High, RuleSeverity.Critical];

    /// <summary>
    /// Actions that admins can add through the MVP rule builder without writing code.
    /// </summary>
    public static readonly RuleActionType[] MvpActions =
    [
        RuleActionType.SetRiskLevel,
        RuleActionType.AddReason,
        RuleActionType.RouteToSafetyPage,
        RuleActionType.Block,
        RuleActionType.Allow,
        RuleActionType.RequireReview
    ];

    /// <summary>
    /// Stable identifier used to save and update the rule.
    /// </summary>
    public string RuleId { get; set; } = "new-domain-shortener-high-risk";

    /// <summary>
    /// Admin-facing rule name.
    /// </summary>
    public string Name { get; set; } = "New Domain With Shortened URL";

    /// <summary>
    /// Short explanation of what the rule is intended to detect.
    /// </summary>
    public string Description { get; set; } = "Flags shortened links that resolve to new domains.";

    /// <summary>
    /// Whether the rule is enabled in its selected mode.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Controls whether the rule watches, actively enforces, or is ignored.
    /// </summary>
    public RuleMode Mode { get; set; } = RuleMode.Watch;

    /// <summary>
    /// Severity used for review, simulation, and risk messaging.
    /// </summary>
    public RuleSeverity Severity { get; set; } = RuleSeverity.High;

    /// <summary>
    /// Conditions that must match before the rule actions can run.
    /// </summary>
    public List<RuleConditionInput> Conditions { get; } = [];

    /// <summary>
    /// Actions applied when every condition matches.
    /// </summary>
    public List<RuleActionInput> Actions { get; } = [];

    /// <summary>
    /// Whether the rule needs administrator approval before enforcement.
    /// </summary>
    public bool RequiresApproval { get; set; } = true;

    /// <summary>
    /// Whether simulation is required before the rule can be enabled.
    /// </summary>
    public bool SimulationRequired { get; set; } = true;

    /// <summary>
    /// Identifier for the admin or system that created the rule.
    /// </summary>
    public string CreatedBy { get; set; } = "admin";

    /// <summary>
    /// Plain-English reason for creating the rule.
    /// </summary>
    public string CreatedReason { get; set; } = "Suspicious shortened URL pattern";

    /// <summary>
    /// Confidence score from simulation or review, where higher means stronger supporting evidence.
    /// </summary>
    public decimal ConfidenceScore { get; set; }

    /// <summary>
    /// Version number used by rule history and rollback workflows.
    /// </summary>
    public int Version { get; set; } = 1;

    /// <summary>
    /// Creates the example shortener rule used by the MVP admin form.
    /// </summary>
    /// <returns>A form model prefilled with a high-risk shortened-URL rule.</returns>
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

    /// <summary>
    /// Converts the form state into a validated structured rule model.
    /// </summary>
    /// <returns>A trust rule with typed conditions, actions, and approval metadata.</returns>
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

    /// <summary>
    /// Loads an existing rule into the form so admins can edit it without losing structured JSON values.
    /// </summary>
    /// <param name="rule">The rule to display in the form.</param>
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

    /// <summary>
    /// Converts a text form value into the closest JSON value type used by the rule engine.
    /// </summary>
    /// <param name="value">The raw form value entered by an admin.</param>
    /// <returns>A JSON element containing a boolean, number, or string.</returns>
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

    /// <summary>
    /// Converts a rule JSON value back to display text for the form.
    /// </summary>
    /// <param name="value">The JSON value stored in a rule condition or action.</param>
    /// <returns>Readable form text for the JSON value.</returns>
    private static string JsonValueText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.True => bool.TrueString.ToLowerInvariant(),
        JsonValueKind.False => bool.FalseString.ToLowerInvariant(),
        JsonValueKind.Number => value.GetRawText(),
        _ => value.ToString()
    };
}

/// <summary>
/// Captures one condition row from the admin rule-builder form.
/// </summary>
public sealed class RuleConditionInput
{
    /// <summary>
    /// Allow-listed fact field that the rule evaluates.
    /// </summary>
    public string Field { get; set; } = "domain.ageDays";

    /// <summary>
    /// Comparison operator used for this condition.
    /// </summary>
    public RuleOperator Operator { get; set; } = RuleOperator.LessThan;

    /// <summary>
    /// Raw form value converted to JSON when the rule is saved.
    /// </summary>
    public string Value { get; set; } = "30";
}

/// <summary>
/// Captures one action row from the admin rule-builder form.
/// </summary>
public sealed class RuleActionInput
{
    /// <summary>
    /// Structured action type supported by the rule engine.
    /// </summary>
    public RuleActionType Type { get; set; } = RuleActionType.SetRiskLevel;

    /// <summary>
    /// Raw form value converted to JSON when the action is saved.
    /// </summary>
    public string Value { get; set; } = "High";
}
