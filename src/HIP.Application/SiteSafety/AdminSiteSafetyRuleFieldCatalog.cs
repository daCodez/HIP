using System.Collections.ObjectModel;
using System.Text.Json;

namespace HIP.Application.SiteSafety;

/// <summary>Runtime value type exposed by one privacy-safe admin-rule field.</summary>
public enum AdminSiteSafetyRuleFieldValueType { String, Boolean, Integer, StringCollection, EnumCollection }

/// <summary>Canonical field name, value type, and compatible operators.</summary>
public sealed record AdminSiteSafetyRuleFieldDefinition(
    string Name,
    AdminSiteSafetyRuleFieldValueType ValueType,
    IReadOnlyCollection<AdminSiteSafetyRuleOperator> Operators);

/// <summary>Single immutable HIP-0402 catalog shared by validation, mapping, and evaluation.</summary>
public static class AdminSiteSafetyRuleFieldCatalog
{
    private const int MaximumListItems = 64;
    private const int MaximumStringLength = 160;
    private static readonly AdminSiteSafetyRuleOperator[] StringOperators =
    [
        AdminSiteSafetyRuleOperator.Equals, AdminSiteSafetyRuleOperator.NotEquals,
        AdminSiteSafetyRuleOperator.Contains, AdminSiteSafetyRuleOperator.StartsWith,
        AdminSiteSafetyRuleOperator.EndsWith, AdminSiteSafetyRuleOperator.InList
    ];
    private static readonly AdminSiteSafetyRuleOperator[] BooleanOperators =
        [AdminSiteSafetyRuleOperator.Equals, AdminSiteSafetyRuleOperator.NotEquals];
    private static readonly AdminSiteSafetyRuleOperator[] IntegerOperators =
    [
        AdminSiteSafetyRuleOperator.Equals, AdminSiteSafetyRuleOperator.NotEquals,
        AdminSiteSafetyRuleOperator.GreaterThan, AdminSiteSafetyRuleOperator.GreaterThanOrEqual,
        AdminSiteSafetyRuleOperator.LessThan, AdminSiteSafetyRuleOperator.LessThanOrEqual,
        AdminSiteSafetyRuleOperator.InList
    ];
    private static readonly AdminSiteSafetyRuleOperator[] CollectionOperators =
        [AdminSiteSafetyRuleOperator.Contains, AdminSiteSafetyRuleOperator.ContainsAny];

    private static readonly IReadOnlyDictionary<string, AdminSiteSafetyRuleFieldDefinition> Definitions =
        new ReadOnlyDictionary<string, AdminSiteSafetyRuleFieldDefinition>(
            new Dictionary<string, AdminSiteSafetyRuleFieldDefinition>(StringComparer.OrdinalIgnoreCase)
            {
                ["Domain"] = Field("Domain", AdminSiteSafetyRuleFieldValueType.String, StringOperators),
                ["Tld"] = Field("Tld", AdminSiteSafetyRuleFieldValueType.String, StringOperators),
                ["HasHttps"] = Field("HasHttps", AdminSiteSafetyRuleFieldValueType.Boolean, BooleanOperators),
                ["RedirectCount"] = Field("RedirectCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["ShortenedLinkCount"] = Field("ShortenedLinkCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["ObfuscatedLinkCount"] = Field("ObfuscatedLinkCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["ExternalScriptCount"] = Field("ExternalScriptCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["InlineScriptCount"] = Field("InlineScriptCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["SuspiciousScriptPatternCount"] = Field("SuspiciousScriptPatternCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["ExecutableDownloadCount"] = Field("ExecutableDownloadCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["ArchiveDownloadCount"] = Field("ArchiveDownloadCount", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["HasLoginForm"] = Field("HasLoginForm", AdminSiteSafetyRuleFieldValueType.Boolean, BooleanOperators),
                ["HasPasswordField"] = Field("HasPasswordField", AdminSiteSafetyRuleFieldValueType.Boolean, BooleanOperators),
                ["HasPaymentField"] = Field("HasPaymentField", AdminSiteSafetyRuleFieldValueType.Boolean, BooleanOperators),
                ["KnownAbuseReports"] = Field("KnownAbuseReports", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["DomainReputationScore"] = Field("DomainReputationScore", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["PageReputationScore"] = Field("PageReputationScore", AdminSiteSafetyRuleFieldValueType.Integer, IntegerOperators),
                ["MatchedRiskTerms"] = Field("MatchedRiskTerms", AdminSiteSafetyRuleFieldValueType.StringCollection, CollectionOperators),
                ["ProviderEvidenceType"] = Field("ProviderEvidenceType", AdminSiteSafetyRuleFieldValueType.EnumCollection, CollectionOperators),
                ["ProviderEvidenceStatus"] = Field("ProviderEvidenceStatus", AdminSiteSafetyRuleFieldValueType.EnumCollection, CollectionOperators)
            });

    public static IReadOnlyCollection<AdminSiteSafetyRuleFieldDefinition> Fields { get; } =
        Array.AsReadOnly(Definitions.Values.OrderBy(value => value.Name, StringComparer.Ordinal).ToArray());

    public static bool TryGet(string? field, out AdminSiteSafetyRuleFieldDefinition definition) =>
        Definitions.TryGetValue(field ?? string.Empty, out definition!);

    public static bool TryValidate(AdminSiteSafetyRuleCondition? condition, out string error)
    {
        if (condition is null || !TryGet(condition.Field, out var field))
        {
            error = "Unsupported or private field.";
            return false;
        }
        if (!Enum.IsDefined(condition.Operator) || !field.Operators.Contains(condition.Operator))
        {
            error = $"Operator {condition.Operator} is not valid for {field.ValueType} field {field.Name}.";
            return false;
        }
        if (!ValueMatches(field.ValueType, condition.Operator, condition.Value))
        {
            error = $"Condition value has the wrong type for {field.Name}.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool ValueMatches(
        AdminSiteSafetyRuleFieldValueType type,
        AdminSiteSafetyRuleOperator ruleOperator,
        JsonElement value)
    {
        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }
        if (ruleOperator is AdminSiteSafetyRuleOperator.InList)
        {
            return ValidArray(value, type is AdminSiteSafetyRuleFieldValueType.Integer);
        }
        if (ruleOperator is AdminSiteSafetyRuleOperator.ContainsAny)
        {
            return ValidArray(value, numbers: false);
        }

        return type switch
        {
            AdminSiteSafetyRuleFieldValueType.Boolean => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            AdminSiteSafetyRuleFieldValueType.Integer => value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out _),
            _ => ValidString(value)
        };
    }

    private static bool ValidArray(JsonElement value, bool numbers)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > MaximumListItems)
        {
            return false;
        }
        return value.EnumerateArray().All(item => numbers
            ? item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out _)
            : ValidString(item));
    }

    private static bool ValidString(JsonElement value) =>
        value.ValueKind == JsonValueKind.String &&
        value.GetString() is { Length: > 0 and <= MaximumStringLength } text &&
        !text.Any(char.IsControl);

    private static AdminSiteSafetyRuleFieldDefinition Field(
        string name,
        AdminSiteSafetyRuleFieldValueType type,
        AdminSiteSafetyRuleOperator[] operators) =>
        new(name, type, Array.AsReadOnly(operators.ToArray()));
}
