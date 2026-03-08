namespace HIP.Security.Domain.Policies;

public sealed record PolicyRule(
    string Key,
    string Operator,
    string Value,
    bool IsEnabled = true);
