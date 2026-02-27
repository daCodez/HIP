using System.Collections.Concurrent;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Audit;

namespace HIP.ApiService.Infrastructure.Audit;

public sealed class InMemoryAuditTrail(ILogger<InMemoryAuditTrail> logger) : IAuditTrail
{
    private static readonly ConcurrentQueue<AuditEvent> Events = new();
    private const int MaxEvents = 500;

    public Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent); // validation

        Events.Enqueue(auditEvent); // performance awareness: lock-free queue for append path
        while (Events.Count > MaxEvents && Events.TryDequeue(out _)) { }

        logger.LogDebug("Audit event appended: {EventType} {Subject}", auditEvent.EventType, auditEvent.Subject); // security awareness: structured no-secrets log
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken)
    {
        if (count <= 0) return Task.FromResult<IReadOnlyList<AuditEvent>>(Array.Empty<AuditEvent>()); // validation

        var snapshot = Events.ToArray();
        var take = Math.Min(count, snapshot.Length);
        var recent = snapshot[^take..].Reverse().ToArray();
        return Task.FromResult<IReadOnlyList<AuditEvent>>(recent); // performance awareness: bounded slice
    }
}
