using System.Text.Json;

namespace HIP.Domain.Rules;

public sealed record RuleAction(
    RuleActionType Type,
    JsonElement Value);
