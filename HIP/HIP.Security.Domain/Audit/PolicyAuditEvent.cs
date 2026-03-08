namespace HIP.Security.Domain.Audit;

public sealed record PolicyAuditEvent(
    Guid EventId,
    Guid PolicyId,
    string Action,
    string Outcome,
    string? ReasonCode,
    DateTimeOffset OccurredAtUtc,
    IReadOnlyDictionary<string, string> Metadata);
