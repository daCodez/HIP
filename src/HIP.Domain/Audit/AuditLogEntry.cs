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
    AuditSeverity Severity)
{
    public string ActorRole { get; init; } = "Unknown";

    public IReadOnlyDictionary<string, string> BeforeMetadata { get; init; } = new Dictionary<string, string>();

    public IReadOnlyDictionary<string, string> AfterMetadata { get; init; } = new Dictionary<string, string>();

    public string? CorrelationId { get; init; }
}
