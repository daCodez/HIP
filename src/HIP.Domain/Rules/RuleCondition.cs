using System.Text.Json;

namespace HIP.Domain.Rules;

public sealed record RuleCondition(string Field, RuleOperator Operator, JsonElement Value);
