using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>
/// Status: Updated
/// Changed: 2026-06-21 09:38 UTC
/// Developer: HIP Development Team
/// Assisted by: Codex
/// Description: Applies safe structured rule actions after a rule matches; it never executes raw code from a rule.
/// </summary>
public sealed class RuleActionApplier(IRuleMatchingEngine matchingEngine) : IRuleActionApplier
{
    private static readonly IReadOnlyDictionary<RuleActionType, Action<RuleActionApplicationState, RuleAction>> ActionHandlers =
        new Dictionary<RuleActionType, Action<RuleActionApplicationState, RuleAction>>
        {
            [RuleActionType.SetRiskLevel] = (state, action) => state.RiskLevel = ParseRiskLevel(Text(action.Value), state.RiskLevel),
            [RuleActionType.AddScorePenalty] = (state, action) => state.ScoreDelta -= Number(action.Value),
            [RuleActionType.AddScoreBonus] = (state, action) => state.ScoreDelta += Number(action.Value),
            [RuleActionType.AddReason] = (state, action) => state.Reasons.Add(Text(action.Value)),
            [RuleActionType.AddWarning] = (state, action) => state.Reasons.Add(Text(action.Value)),
            [RuleActionType.RouteToSafetyPage] = (state, action) => state.RouteToSafetyPage = Boolean(action.Value),
            [RuleActionType.Block] = ApplyBlock,
            [RuleActionType.Allow] = ApplyAllow,
            [RuleActionType.RequireReview] = (state, action) => state.RequiresReview = Boolean(action.Value),
            [RuleActionType.MarkForSimulation] = (state, action) => state.MarkedForSimulation = Boolean(action.Value)
        };

    /// <inheritdoc />
    public AppliedRuleResult Apply(TrustRule rule, FactSet facts)
    {
        var match = matchingEngine.Match(rule, facts);
        if (!match.IsMatch || rule.Mode == RuleMode.Watch)
        {
            return new AppliedRuleResult(rule, match.IsMatch, RiskStatus.Unknown, 0, [], false, false, rule.SimulationRequired);
        }

        var state = new RuleActionApplicationState(rule.SimulationRequired);

        foreach (var action in rule.Actions)
        {
            ApplyKnownAction(state, action);
        }

        return new AppliedRuleResult(rule, true, state.RiskLevel, state.ScoreDelta, state.Reasons, state.RouteToSafetyPage, state.RequiresReview, state.MarkedForSimulation);
    }

    /// <summary>
    /// Applies one known structured action and ignores unknown action values so a bad enum cast cannot crash scanning.
    /// </summary>
    /// <param name="state">The rule result being built.</param>
    /// <param name="action">The structured action from the rule.</param>
    private static void ApplyKnownAction(RuleActionApplicationState state, RuleAction action)
    {
        if (ActionHandlers.TryGetValue(action.Type, out var handler))
        {
            handler(state, action);
        }
    }

    /// <summary>
    /// Applies the explicit block action, which always routes through safety review and requires human review.
    /// </summary>
    /// <param name="state">The rule result being built.</param>
    /// <param name="_">The block action; the value is intentionally ignored.</param>
    private static void ApplyBlock(RuleActionApplicationState state, RuleAction _)
    {
        state.RiskLevel = RiskStatus.Critical;
        state.RouteToSafetyPage = true;
        state.RequiresReview = true;
        state.Reasons.Add("Rule action blocked this target.");
    }

    /// <summary>
    /// Applies the explicit allow action without adding trust beyond the existing ProbablySafe label.
    /// </summary>
    /// <param name="state">The rule result being built.</param>
    /// <param name="_">The allow action; the value is intentionally ignored.</param>
    private static void ApplyAllow(RuleActionApplicationState state, RuleAction _)
    {
        state.RiskLevel = RiskStatus.ProbablySafe;
        state.RouteToSafetyPage = false;
    }

    /// <summary>
    /// Converts a rule action value to display text using the shared safe converter.
    /// </summary>
    /// <param name="value">The JSON value from the rule action.</param>
    /// <returns>A stable text value for labels, reasons, and risk parsing.</returns>
    private static string Text(System.Text.Json.JsonElement value) => RuleValueConverter.Text(value);

    /// <summary>
    /// Converts a rule action value to a score amount without throwing on bad admin input.
    /// </summary>
    /// <param name="value">The JSON value from the rule action.</param>
    /// <returns>The score amount, or zero when the value is not a number.</returns>
    private static int Number(System.Text.Json.JsonElement value) => RuleValueConverter.Int32(value);

    /// <summary>
    /// Converts a rule action value to a boolean for simple on/off effects.
    /// </summary>
    /// <param name="value">The JSON value from the rule action.</param>
    /// <returns><see langword="true" /> only when the action value clearly asks for it.</returns>
    private static bool Boolean(System.Text.Json.JsonElement value) => RuleValueConverter.Boolean(value);

    /// <summary>
    /// Converts rule text into the current risk label while keeping old "High" JSON rules compatible.
    /// </summary>
    /// <param name="value">The risk label from the rule JSON.</param>
    /// <param name="fallback">The current risk level when parsing fails.</param>
    /// <returns>The parsed risk level, or the fallback value when the label is not supported.</returns>
    private static RiskStatus ParseRiskLevel(string value, RiskStatus fallback)
    {
        if (value.Equals("High", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("Suspicious", StringComparison.OrdinalIgnoreCase))
        {
            return RiskStatus.HighRisk;
        }

        return Enum.TryParse<RiskStatus>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    /// <summary>
    /// Holds the running result while a matched rule action list is applied.
    /// </summary>
    private sealed class RuleActionApplicationState(bool markedForSimulation)
    {
        /// <summary>
        /// Gets or sets the strongest risk level set by the rule actions.
        /// </summary>
        public RiskStatus RiskLevel { get; set; } = RiskStatus.Unknown;

        /// <summary>
        /// Gets or sets the score change created by the rule actions.
        /// </summary>
        public int ScoreDelta { get; set; }

        /// <summary>
        /// Gets privacy-safe reasons and warnings created by the rule actions.
        /// </summary>
        public List<string> Reasons { get; } = [];

        /// <summary>
        /// Gets or sets whether users should be routed through the HIP safety page.
        /// </summary>
        public bool RouteToSafetyPage { get; set; }

        /// <summary>
        /// Gets or sets whether this rule result should be reviewed by an admin.
        /// </summary>
        public bool RequiresReview { get; set; }

        /// <summary>
        /// Gets or sets whether this rule still needs simulation before enforcement.
        /// </summary>
        public bool MarkedForSimulation { get; set; } = markedForSimulation;
    }
}
