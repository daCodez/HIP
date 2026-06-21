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

    /// <summary>
    /// Converts a JSON rule value to an integer for score changes; invalid values become zero instead of throwing during scans.
    /// </summary>
    /// <param name="value">The JSON value stored in the rule action.</param>
    /// <returns>The parsed integer, or zero when the rule value is not a number.</returns>
    public static int Int32(JsonElement value) =>
        value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : 0;

    /// <summary>
    /// Converts a JSON rule value to a boolean for route, review, and simulation actions.
    /// </summary>
    /// <param name="value">The JSON value stored in the rule action.</param>
    /// <returns><see langword="true" /> only when the value is clearly true.</returns>
    public static bool Boolean(JsonElement value) =>
        value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false
        };
}
