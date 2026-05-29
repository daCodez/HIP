using HIP.Domain.Audit;

namespace HIP.Application.Review;

public interface IAuditLogRepository
{
    Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken);
}
