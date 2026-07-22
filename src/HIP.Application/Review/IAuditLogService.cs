using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAuditLogService
{
    /// <summary>
    /// Creates a sanitized audit entry without persisting it so a caller can commit it atomically with domain state.
    /// </summary>
    AuditLogEntry CreateEntry(
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null);

    AuditLogEntry Write(
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null);

    /// <summary>
    /// Lists audit entries without blocking the caller's synchronization context.
    /// </summary>
    Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken);

    IReadOnlyCollection<AuditLogEntry> List();
}
