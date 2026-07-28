using HIP.Domain.Audit;

namespace HIP.Application.Review;

public interface IAuditLogRepository
{
    Task SaveAsync(AuditLogEntry entry, CancellationToken cancellationToken);

    Task<bool> TryCreateAsync(AuditLogEntry entry, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken);

    /// <summary>Atomically reseals one known legacy defect and appends its repair attestation.</summary>
    Task<bool> TryRepairKnownIntegrityDefectAsync(
        AuditLogEntry original,
        AuditLogEntry repaired,
        AuditLogEntry attestation,
        CancellationToken cancellationToken) =>
        Task.FromResult(false);
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

    public Task<bool> TryRepairKnownIntegrityDefectAsync(
        AuditLogEntry original,
        AuditLogEntry repaired,
        AuditLogEntry attestation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (!entries.TryGetValue(original.AuditLogId, out var current) ||
                current != original ||
                repaired.AuditLogId != original.AuditLogId ||
                entries.ContainsKey(attestation.AuditLogId))
            {
                return Task.FromResult(false);
            }

            entries[repaired.AuditLogId] = repaired;
            entries.Add(attestation.AuditLogId, attestation);
            return Task.FromResult(true);
        }
    }
}
