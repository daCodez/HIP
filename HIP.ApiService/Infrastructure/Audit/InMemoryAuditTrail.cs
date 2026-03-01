using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;

namespace HIP.ApiService.Infrastructure.Audit;

/// <summary>
/// In-memory audit trail used for lightweight/local scenarios.
/// </summary>
public sealed class InMemoryAuditTrail(ILogger<InMemoryAuditTrail> logger) : IAuditTrail
{
    private static readonly ConcurrentQueue<AuditEvent> Events = new();
    private const int MaxEvents = 500;

    /// <inheritdoc />
    public Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        Events.Enqueue(auditEvent);
        while (Events.Count > MaxEvents && Events.TryDequeue(out _)) { }

        logger.LogDebug("Audit event appended: {EventType} {Subject}", auditEvent.EventType, auditEvent.Subject);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken)
    {
        if (count <= 0) return Task.FromResult<IReadOnlyList<AuditEvent>>(Array.Empty<AuditEvent>());

        var snapshot = Events.ToArray();
        var take = Math.Min(count, snapshot.Length);
        var recent = snapshot[^take..].Reverse().ToArray();
        return Task.FromResult<IReadOnlyList<AuditEvent>>(recent);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var take = Math.Clamp(query.Take, 1, 200);
        IEnumerable<AuditEvent> filtered = Events.ToArray();

        if (!string.IsNullOrWhiteSpace(query.EventType))
        {
            filtered = filtered.Where(x => string.Equals(x.EventType, query.EventType, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(query.IdentityId))
        {
            filtered = filtered.Where(x => string.Equals(x.Subject, query.IdentityId, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(query.Outcome))
        {
            filtered = filtered.Where(x => string.Equals(x.Outcome, query.Outcome, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(query.ReasonCode))
        {
            filtered = filtered.Where(x => string.Equals(x.ReasonCode, query.ReasonCode, StringComparison.OrdinalIgnoreCase));
        }

        if (query.FromUtc is not null)
        {
            filtered = filtered.Where(x => x.CreatedAtUtc >= query.FromUtc.Value);
        }

        if (query.ToUtc is not null)
        {
            filtered = filtered.Where(x => x.CreatedAtUtc <= query.ToUtc.Value);
        }

        var items = filtered
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(take)
            .ToArray();

        return Task.FromResult<IReadOnlyList<AuditEvent>>(items);
    }
}
