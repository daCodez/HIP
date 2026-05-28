using System.Collections.Concurrent;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class AuditLogService : IAuditLogService
{
    private readonly ConcurrentDictionary<string, AuditLogEntry> _entries = new();

    public AuditLogEntry Write(string actorId, string action, TargetType targetType, string targetId, string summary, AuditSeverity severity, IReadOnlyDictionary<string, string>? metadata = null)
    {
        var entry = new AuditLogEntry(
            $"audit-{Guid.NewGuid():N}",
            string.IsNullOrWhiteSpace(actorId) ? "system" : actorId,
            action,
            targetType,
            targetId,
            summary,
            DateTimeOffset.UtcNow,
            metadata ?? new Dictionary<string, string>(),
            severity);

        _entries[entry.AuditLogId] = entry;
        return entry;
    }

    public IReadOnlyCollection<AuditLogEntry> List() =>
        _entries.Values.OrderByDescending(entry => entry.CreatedAtUtc).ToArray();
}
