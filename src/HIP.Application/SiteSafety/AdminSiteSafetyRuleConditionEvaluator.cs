using System.Text.Json;

namespace HIP.Application.SiteSafety;

/// <summary>
/// NEW 2026-06-21 00:00 UTC - HIP Development Team, assisted by Codex:
/// Evaluates one admin-created Site Safety condition against privacy-safe scan facts.
/// This keeps admin rules as safe data instead of executable code.
/// </summary>
public static class AdminSiteSafetyRuleConditionEvaluator
{
    /// <summary>
    /// Checks whether a condition matches the current scan input.
    /// </summary>
    /// <param name="condition">The structured condition saved by an admin rule.</param>
    /// <param name="input">Privacy-safe facts collected by HIP scanning.</param>
    /// <returns>True when the allow-listed field satisfies the safe operator; otherwise false.</returns>
    public static bool Matches(AdminSiteSafetyRuleCondition condition, SiteSafetyRuleInput input)
    {
        var actual = FieldValue(condition.Field, input);
        return condition.Operator switch
        {
            AdminSiteSafetyRuleOperator.Equals => EqualsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.NotEquals => !EqualsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.GreaterThan => CompareNumber(actual, condition.Value, value => value > 0),
            AdminSiteSafetyRuleOperator.GreaterThanOrEqual => CompareNumber(actual, condition.Value, value => value >= 0),
            AdminSiteSafetyRuleOperator.LessThan => CompareNumber(actual, condition.Value, value => value < 0),
            AdminSiteSafetyRuleOperator.LessThanOrEqual => CompareNumber(actual, condition.Value, value => value <= 0),
            AdminSiteSafetyRuleOperator.Contains => ContainsValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.ContainsAny => ContainsAnyValue(actual, condition.Value),
            AdminSiteSafetyRuleOperator.StartsWith => actual?.ToString()?.StartsWith(condition.Value.ToString(), StringComparison.OrdinalIgnoreCase) == true,
            AdminSiteSafetyRuleOperator.EndsWith => actual?.ToString()?.EndsWith(condition.Value.ToString(), StringComparison.OrdinalIgnoreCase) == true,
            AdminSiteSafetyRuleOperator.InList => InList(actual, condition.Value),
            _ => false
        };
    }

    /// <summary>
    /// Builds the simulation diagnostics admins see for a single condition.
    /// </summary>
    /// <param name="condition">The structured condition saved by an admin rule.</param>
    /// <param name="input">Privacy-safe facts collected by HIP scanning.</param>
    /// <returns>A plain-English condition result without private page content.</returns>
    public static AdminSiteSafetyRuleConditionSimulationResult Describe(AdminSiteSafetyRuleCondition condition, SiteSafetyRuleInput input)
    {
        var actual = FieldValue(condition.Field, input);
        var matched = Matches(condition, input);
        var expectedValue = condition.Value.ToString();
        var actualValue = DisplayValue(actual);
        var description = $"{condition.Field} {condition.Operator} {expectedValue} (actual: {actualValue})";

        return new AdminSiteSafetyRuleConditionSimulationResult(
            condition.Field,
            condition.Operator,
            expectedValue,
            actualValue,
            matched,
            description);
    }

    /// <summary>
    /// Gets a safe field value from the rule input.
    /// </summary>
    /// <param name="field">The allow-listed field name from the admin rule.</param>
    /// <param name="input">Privacy-safe facts collected by HIP scanning.</param>
    /// <returns>The matching value, or null when the field is not allow-listed.</returns>
    private static object? FieldValue(string field, SiteSafetyRuleInput input) => field switch
    {
        "Domain" => input.Domain,
        "Tld" => input.Tld,
        "HasHttps" => input.HasHttps,
        "RedirectCount" => input.RedirectCount,
        "ShortenedLinkCount" => input.ShortenedLinkCount,
        "ObfuscatedLinkCount" => input.ObfuscatedLinkCount,
        "ExternalScriptCount" => input.ExternalScriptCount,
        "InlineScriptCount" => input.InlineScriptCount,
        "SuspiciousScriptPatternCount" => input.SuspiciousScriptPatternCount,
        "ExecutableDownloadCount" => input.ExecutableDownloadCount,
        "ArchiveDownloadCount" => input.ArchiveDownloadCount,
        "HasLoginForm" => input.HasLoginForm,
        "HasPasswordField" => input.HasPasswordField,
        "HasPaymentField" => input.HasPaymentField,
        "KnownAbuseReports" => input.KnownAbuseReports,
        "DomainReputationScore" => input.DomainReputationScore,
        "PageReputationScore" => input.PageReputationScore,
        "MatchedRiskTerms" => input.MatchedRiskTerms,
        "ProviderEvidenceType" => input.ProviderEvidence.Select(item => item.ProviderType.ToString()).ToArray(),
        "ProviderEvidenceStatus" => input.ProviderEvidence.SelectMany(item => item.EvidenceItems).Select(item => item.Status.ToString()).ToArray(),
        _ => null
    };

    /// <summary>
    /// Formats allow-listed simulation facts for admin diagnostics without exposing private content.
    /// </summary>
    /// <param name="value">The safe value pulled from the scan input.</param>
    /// <returns>A short display value for simulation output.</returns>
    private static string DisplayValue(object? value) =>
        value switch
        {
            null => "not set",
            IEnumerable<string> values => string.Join(", ", values),
            _ => value.ToString() ?? "not set"
        };

    /// <summary>
    /// Compares scalar values without unsafe expression evaluation.
    /// </summary>
    /// <param name="actual">The safe value from HIP scan input.</param>
    /// <param name="expected">The structured JSON value from the admin rule.</param>
    /// <returns>True when the values are equal using type-aware comparison.</returns>
    private static bool EqualsValue(object? actual, JsonElement expected) =>
        actual switch
        {
            bool value => expected.ValueKind == JsonValueKind.True && value || expected.ValueKind == JsonValueKind.False && !value,
            int value => expected.TryGetInt32(out var expectedNumber) && value == expectedNumber,
            string value => string.Equals(value, expected.ToString(), StringComparison.OrdinalIgnoreCase),
            _ => string.Equals(actual?.ToString(), expected.ToString(), StringComparison.OrdinalIgnoreCase)
        };

    /// <summary>
    /// Compares numeric values with a caller-provided comparison predicate.
    /// </summary>
    /// <param name="actual">The safe value from HIP scan input.</param>
    /// <param name="expected">The structured JSON number from the admin rule.</param>
    /// <param name="comparison">The comparison to apply to the numeric difference.</param>
    /// <returns>True when both values are numbers and the comparison passes.</returns>
    private static bool CompareNumber(object? actual, JsonElement expected, Func<int, bool> comparison)
    {
        if (!expected.TryGetInt32(out var expectedNumber) || actual is not int actualNumber)
        {
            return false;
        }

        return comparison(actualNumber.CompareTo(expectedNumber));
    }

    /// <summary>
    /// Checks whether a scalar or collection contains a string value.
    /// </summary>
    /// <param name="actual">The safe value from HIP scan input.</param>
    /// <param name="expected">The structured JSON value from the admin rule.</param>
    /// <returns>True when the expected text appears in the actual value.</returns>
    private static bool ContainsValue(object? actual, JsonElement expected)
    {
        var expectedValue = expected.ToString();
        return actual switch
        {
            string value => value.Contains(expectedValue, StringComparison.OrdinalIgnoreCase),
            IEnumerable<string> values => values.Any(value => value.Contains(expectedValue, StringComparison.OrdinalIgnoreCase)),
            _ => false
        };
    }

    /// <summary>
    /// Checks whether a collection field contains at least one expected value.
    /// </summary>
    /// <param name="actual">The safe value from HIP scan input.</param>
    /// <param name="expected">The structured JSON array from the admin rule.</param>
    /// <returns>True when any expected item appears in the actual collection.</returns>
    private static bool ContainsAnyValue(object? actual, JsonElement expected)
    {
        if (actual is not IEnumerable<string> values || expected.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var actualValues = values.ToArray();
        return expected.EnumerateArray().Any(item => actualValues.Contains(item.ToString(), StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks whether the actual scalar value is listed in an expected array.
    /// </summary>
    /// <param name="actual">The safe value from HIP scan input.</param>
    /// <param name="expected">The structured JSON array from the admin rule.</param>
    /// <returns>True when the actual value is present in the expected list.</returns>
    private static bool InList(object? actual, JsonElement expected) =>
        expected.ValueKind == JsonValueKind.Array &&
        expected.EnumerateArray().Any(item => string.Equals(actual?.ToString(), item.ToString(), StringComparison.OrdinalIgnoreCase));
}
