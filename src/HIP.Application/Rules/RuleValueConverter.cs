using System.Globalization;
using System.Text.Json;

namespace HIP.Application.Rules;

/// <summary>
/// Status: New
/// Changed: 2026-06-21 09:33 UTC
/// Developer: HIP Development Team
/// Assisted by: Codex
/// Description: Converts rule values to plain .NET values in one place so rule matching and action handling stay consistent.
/// </summary>
internal static class RuleValueConverter
{
    /// <summary>
    /// Converts a stored or observed value to text using invariant formatting so rules behave the same across machines.
    /// </summary>
    /// <param name="value">The observed value from the scan facts.</param>
    /// <returns>A stable text representation for rule comparisons.</returns>
    public static string Text(object? value) => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;

    /// <summary>
    /// Converts a JSON rule value to text without exposing raw private page data.
    /// </summary>
    /// <param name="value">The JSON value stored in the rule.</param>
    /// <returns>A stable text representation for rule comparisons and summaries.</returns>
    public static string Text(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString() ?? string.Empty,
        JsonValueKind.True => bool.TrueString,
        JsonValueKind.False => bool.FalseString,
        JsonValueKind.Number => value.GetRawText(),
        _ => value.ToString()
    };
}
