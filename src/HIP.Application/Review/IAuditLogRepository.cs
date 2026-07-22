using HIP.Domain.Audit;

namespace HIP.Application.Review;

public interface IAuditLogRepository
{
    Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken);

    Task<bool> TryCreateAsync(AuditLogEntry entry, CancellationToken cancellationToken);

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
            if (!entries.TryAdd(entry.AuditLogId, entry))
            {
                throw new InvalidOperationException("Audit entries are append-only.");
            }
        }

        return Task.CompletedTask;
    }

    public Task<bool> TryCreateAsync(AuditLogEntry entry, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult(entries.TryAdd(entry.AuditLogId, entry));
        }
    }

    public Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<AuditLogEntry>>(entries.Values.ToArray());
        }
    }
}
