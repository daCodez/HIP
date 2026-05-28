using System.Globalization;
using System.Text.Json;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class RuleMatchingEngine : IRuleMatchingEngine
{
    public RuleMatchResult Match(TrustRule rule, FactSet facts)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(facts);

        if (!rule.Enabled || rule.Mode == RuleMode.Disabled)
        {
            return new RuleMatchResult(rule, false, [], ["rule.disabled"]);
        }

        var matched = new List<string>();
        var failed = new List<string>();

        foreach (var condition in rule.Conditions)
        {
            if (!facts.TryGetValue(condition.Field, out var factValue) ||
                !Evaluate(factValue, condition.Operator, condition.Value))
            {
                failed.Add(condition.Field);
                continue;
            }

            matched.Add(condition.Field);
        }

        return new RuleMatchResult(rule, failed.Count == 0, matched, failed);
    }

    private static bool Evaluate(object? factValue, RuleOperator ruleOperator, JsonElement expected) => ruleOperator switch
    {
        RuleOperator.Equals => ValuesEqual(factValue, expected),
        RuleOperator.NotEquals => !ValuesEqual(factValue, expected),
        RuleOperator.GreaterThan => Compare(factValue, expected) > 0,
        RuleOperator.GreaterThanOrEqual => Compare(factValue, expected) >= 0,
        RuleOperator.LessThan => Compare(factValue, expected) < 0,
        RuleOperator.LessThanOrEqual => Compare(factValue, expected) <= 0,
        RuleOperator.Contains => Text(factValue).Contains(Text(expected), StringComparison.OrdinalIgnoreCase),
        RuleOperator.StartsWith => Text(factValue).StartsWith(Text(expected), StringComparison.OrdinalIgnoreCase),
        RuleOperator.EndsWith => Text(factValue).EndsWith(Text(expected), StringComparison.OrdinalIgnoreCase),
        _ => false
    };

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

        return string.Equals(Text(factValue), Text(expected), StringComparison.OrdinalIgnoreCase);
    }

    private static int Compare(object? factValue, JsonElement expected)
    {
        if (!decimal.TryParse(Convert.ToString(factValue, CultureInfo.InvariantCulture), NumberStyles.Number, CultureInfo.InvariantCulture, out var factNumber) ||
            !expected.TryGetDecimal(out var expectedNumber))
        {
            return string.Compare(Text(factValue), Text(expected), StringComparison.OrdinalIgnoreCase);
        }

        return factNumber.CompareTo(expectedNumber);
    }

    private static string Text(object? value) => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;

    private static string Text(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.True => bool.TrueString,
        JsonValueKind.False => bool.FalseString,
        JsonValueKind.Number => value.GetRawText(),
        _ => value.ToString()
    };
}
