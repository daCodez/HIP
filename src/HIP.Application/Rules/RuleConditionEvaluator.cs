using System.Globalization;
using System.Text.Json;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>
/// Status: New
/// Changed: 2026-06-21 09:33 UTC
/// Developer: HIP Development Team
/// Assisted by: Codex
/// Description: Holds the built-in JSON rule operators so new operators can be reviewed and tested without changing the matching loop.
/// </summary>
public sealed class RuleConditionEvaluator : IRuleConditionEvaluator
{
    private static readonly IReadOnlyDictionary<RuleOperator, Func<object?, JsonElement, bool>> Operators =
        new Dictionary<RuleOperator, Func<object?, JsonElement, bool>>
        {
            [RuleOperator.Equals] = ValuesEqual,
            [RuleOperator.NotEquals] = (factValue, expected) => !ValuesEqual(factValue, expected),
            [RuleOperator.GreaterThan] = (factValue, expected) => Compare(factValue, expected) > 0,
            [RuleOperator.GreaterThanOrEqual] = (factValue, expected) => Compare(factValue, expected) >= 0,
            [RuleOperator.LessThan] = (factValue, expected) => Compare(factValue, expected) < 0,
            [RuleOperator.LessThanOrEqual] = (factValue, expected) => Compare(factValue, expected) <= 0,
            [RuleOperator.Contains] = (factValue, expected) => RuleValueConverter.Text(factValue).Contains(RuleValueConverter.Text(expected), StringComparison.OrdinalIgnoreCase),
            [RuleOperator.StartsWith] = (factValue, expected) => RuleValueConverter.Text(factValue).StartsWith(RuleValueConverter.Text(expected), StringComparison.OrdinalIgnoreCase),
            [RuleOperator.EndsWith] = (factValue, expected) => RuleValueConverter.Text(factValue).EndsWith(RuleValueConverter.Text(expected), StringComparison.OrdinalIgnoreCase)
        };

    /// <inheritdoc />
    public bool IsMatch(object? factValue, RuleOperator ruleOperator, JsonElement expected) =>
        Operators.TryGetValue(ruleOperator, out var evaluator) && evaluator(factValue, expected);

    /// <summary>
    /// Compares booleans, numbers, and text without letting string casing create avoidable false negatives.
    /// </summary>
    /// <param name="factValue">The value observed by HIP.</param>
    /// <param name="expected">The expected value from the rule JSON.</param>
    /// <returns><see langword="true" /> when both values represent the same value.</returns>
    private static bool ValuesEqual(object? factValue, JsonElement expected)
    {
        if (expected.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            return factValue is bool value && value == expected.GetBoolean();
        }

        if (expected.ValueKind == JsonValueKind.Number)
        {
            return decimal.TryParse(Convert.ToString(factValue, CultureInfo.InvariantCulture), NumberStyles.Number, CultureInfo.InvariantCulture, out var factNumber) &&
                   expected.TryGetDecimal(out var expectedNumber) &&
                   factNumber == expectedNumber;
        }

        return string.Equals(RuleValueConverter.Text(factValue), RuleValueConverter.Text(expected), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Compares numeric values when possible and falls back to text comparison for non-numeric rule values.
    /// </summary>
    /// <param name="factValue">The value observed by HIP.</param>
    /// <param name="expected">The expected value from the rule JSON.</param>
    /// <returns>A normal comparison value less than, equal to, or greater than zero.</returns>
    private static int Compare(object? factValue, JsonElement expected)
    {
        if (!decimal.TryParse(Convert.ToString(factValue, CultureInfo.InvariantCulture), NumberStyles.Number, CultureInfo.InvariantCulture, out var factNumber) ||
            !expected.TryGetDecimal(out var expectedNumber))
        {
            return string.Compare(RuleValueConverter.Text(factValue), RuleValueConverter.Text(expected), StringComparison.OrdinalIgnoreCase);
        }

        return factNumber.CompareTo(expectedNumber);
    }
}
