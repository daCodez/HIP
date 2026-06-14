using HIP.Domain.Audit;

namespace HIP.Application.Review;

public interface IAuditLogRepository
{
    Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken);
}

public sealed class InMemoryAuditLogRepository : IAuditLogRepository
{
    private readonly Dictionary<string, AuditLogEntry> entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    public Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            entries[entry.AuditLogId] = entry;
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<AuditLogEntry>>(entries.Values.ToArray());
        }
    }
}
