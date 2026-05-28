using HIP.Domain.Review;

namespace HIP.Domain.Audit;

public sealed record AuditLogEntry(
    string AuditLogId,
    string ActorId,
    string Action,
    TargetType TargetType,
    string TargetId,
    string Summary,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyDictionary<string, string> Metadata,
    AuditSeverity Severity);
