namespace HIP.Security.Domain.Scenarios;

public sealed record ThreatScenario(
    Guid Id,
    string Name,
    string Description,
    IReadOnlyList<string> AttackSteps,
    IReadOnlyList<string> Tags,
    DateTimeOffset CreatedAtUtc);
