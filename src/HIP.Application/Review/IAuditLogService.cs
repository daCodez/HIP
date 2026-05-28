using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAuditLogService
{
    AuditLogEntry Write(string actorId, string action, TargetType targetType, string targetId, string summary, AuditSeverity severity, IReadOnlyDictionary<string, string>? metadata = null);

    IReadOnlyCollection<AuditLogEntry> List();
}
