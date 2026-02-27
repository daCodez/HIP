using HIP.ApiService.Application.Audit;

namespace HIP.ApiService.Application.Abstractions;

public interface IAuditTrail
{
    Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken);
    Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken);
}
