using System.Text.Json;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>
/// Status: New
/// Changed: 2026-06-21 09:33 UTC
/// Developer: HIP Development Team
/// Assisted by: Codex
/// Description: Checks one rule condition in one shared place so live rule checks and simulations read the same rule the same way.
/// </summary>
public interface IRuleConditionEvaluator
{
    /// <summary>
    /// Evaluates one allow-listed rule operator against one privacy-safe fact value.
    /// </summary>
    /// <param name="factValue">The privacy-safe value collected for the rule field.</param>
    /// <param name="ruleOperator">The structured operator chosen by the rule author.</param>
    /// <param name="expected">The expected JSON value stored in the rule.</param>
    /// <returns><see langword="true" /> when the condition matches; otherwise <see langword="false" />.</returns>
    bool IsMatch(object? factValue, RuleOperator ruleOperator, JsonElement expected);
}
