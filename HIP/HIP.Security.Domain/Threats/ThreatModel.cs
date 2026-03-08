namespace HIP.Security.Domain.Threats;

public sealed record ThreatModel(
    Guid Id,
    string Name,
    ThreatType Type,
    string Description,
    string Severity,
    DateTimeOffset CreatedAtUtc);
