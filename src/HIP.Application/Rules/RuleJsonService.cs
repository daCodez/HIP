using System.Text.Json;
using System.Text.Json.Serialization;
using FluentValidation;
using FluentValidation.Results;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed class RuleJsonService(IValidator<TrustRule> validator) : IRuleJsonService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public string ToJson(TrustRule rule) => JsonSerializer.Serialize(rule, JsonOptions);

    public bool TryParse(string json, out TrustRule? rule, out IReadOnlyCollection<string> errors)
    {
        rule = null;
        errors = [];

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var parseErrors = ValidateRawEnums(root);
            if (parseErrors.Count > 0)
            {
                errors = parseErrors;
                return false;
            }

            rule = JsonSerializer.Deserialize<TrustRule>(json, JsonOptions);
            if (rule is null)
            {
                errors = ["Rule JSON did not contain a valid rule."];
                return false;
            }

            var validation = Validate(rule);
            if (!validation.IsValid)
            {
                errors = validation.Errors.Select(error => error.ErrorMessage).ToArray();
                return false;
            }

            return true;
        }
        catch (JsonException ex)
        {
            errors = [$"Invalid JSON: {ex.Message}"];
            return false;
        }
    }

    public ValidationResult Validate(TrustRule rule) => validator.Validate(rule);

    private static List<string> ValidateRawEnums(JsonElement root)
    {
        var errors = new List<string>();

        if (root.TryGetProperty("mode", out var mode) &&
            !Enum.TryParse<RuleMode>(ReadString(mode), ignoreCase: true, out _))
        {
            errors.Add("Unsupported rule mode.");
        }

        if (root.TryGetProperty("severity", out var severity) &&
            !Enum.TryParse<RuleSeverity>(ReadString(severity), ignoreCase: true, out _))
        {
            errors.Add("Unsupported severity.");
        }

        if (root.TryGetProperty("conditions", out var conditions))
        {
            foreach (var condition in conditions.EnumerateArray())
            {
                if (condition.TryGetProperty("operator", out var ruleOperator) &&
                    !Enum.TryParse<RuleOperator>(ReadString(ruleOperator), ignoreCase: true, out _))
                {
                    errors.Add("Unsupported operator.");
                }
            }
        }

        if (root.TryGetProperty("actions", out var actions))
        {
            foreach (var action in actions.EnumerateArray())
            {
                if (action.TryGetProperty("type", out var type) &&
                    !Enum.TryParse<RuleActionType>(ReadString(type), ignoreCase: true, out _))
                {
                    errors.Add("Unsupported action.");
                }
            }
        }

        return errors;
    }

    private static string? ReadString(JsonElement element) =>
        element.ValueKind == JsonValueKind.String ? element.GetString() : null;
}
