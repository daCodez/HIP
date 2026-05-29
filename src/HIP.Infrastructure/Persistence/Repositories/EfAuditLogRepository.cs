using HIP.Application.Review;
using HIP.Domain.Audit;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfAuditLogRepository(HipRecordStore store) : IAuditLogRepository
{
    private const string Partition = "audit-log";

    public Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, entry.AuditLogId, entry, cancellationToken);

    public Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AuditLogEntry>(Partition, cancellationToken);
}
