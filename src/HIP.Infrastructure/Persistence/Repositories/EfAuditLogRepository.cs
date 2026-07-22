using HIP.Application.Review;
using HIP.Domain.Audit;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfAuditLogRepository(HipRecordStore store) : IAuditLogRepository
{
    private const string Partition = "audit-log";

    public async Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken)
    {
        if (!await TryCreateAsync(entry, cancellationToken))
        {
            throw new InvalidOperationException("Audit entries are append-only.");
        }
    }

    public Task<bool> TryCreateAsync(AuditLogEntry entry, CancellationToken cancellationToken) =>
        store.TrySaveVersionedAsync(
            Partition,
            entry.AuditLogId,
            entry,
            0,
            1,
            cancellationToken);

    public Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AuditLogEntry>(Partition, cancellationToken);
}
