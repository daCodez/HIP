using HIP.ApiService.Application.Abstractions;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Audit;

/// <summary>
/// Entity Framework-backed audit trail implementation.
/// </summary>
public sealed class DatabaseAuditTrail(HipDbContext dbContext) : IAuditTrail
{
    /// <inheritdoc />
    public async Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        dbContext.AuditEvents.Add(new AuditEventRecord
        {
            Id = auditEvent.Id,
            CreatedAtUtc = auditEvent.CreatedAtUtc,
            EventType = auditEvent.EventType,
            Subject = auditEvent.Subject,
            Source = auditEvent.Source,
            Detail = auditEvent.Detail,
            Category = auditEvent.Category,
            Outcome = auditEvent.Outcome,
            ReasonCode = auditEvent.ReasonCode,
            Route = auditEvent.Route,
            CorrelationId = auditEvent.CorrelationId,
            LatencyMs = auditEvent.LatencyMs
        });

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken)
    {
        var take = Math.Clamp(count, 1, 200);

        var rows = await dbContext.AuditEvents
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return rows
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(take)
            .Select(Map)
            .ToArray();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var take = Math.Clamp(query.Take, 1, 200);
        var q = dbContext.AuditEvents.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(query.EventType))
        {
            q = q.Where(x => x.EventType == query.EventType);
        }

        if (!string.IsNullOrWhiteSpace(query.IdentityId))
        {
            q = q.Where(x => x.Subject == query.IdentityId);
        }

        if (!string.IsNullOrWhiteSpace(query.Outcome))
        {
            q = q.Where(x => x.Outcome == query.Outcome);
        }

        if (!string.IsNullOrWhiteSpace(query.ReasonCode))
        {
            q = q.Where(x => x.ReasonCode == query.ReasonCode);
        }

        var rows = await q.ToListAsync(cancellationToken);

        if (query.FromUtc is not null)
        {
            rows = rows.Where(x => x.CreatedAtUtc >= query.FromUtc.Value).ToList();
        }

        if (query.ToUtc is not null)
        {
            rows = rows.Where(x => x.CreatedAtUtc <= query.ToUtc.Value).ToList();
        }

        return rows
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(take)
            .Select(Map)
            .ToArray();
    }

    private static AuditEvent Map(AuditEventRecord row) =>
        new(
            row.Id,
            row.CreatedAtUtc,
            row.EventType,
            row.Subject,
            row.Source,
            row.Detail,
            row.Category,
            row.Outcome,
            row.ReasonCode,
            row.Route,
            row.CorrelationId,
            row.LatencyMs);
}
