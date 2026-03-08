using System.Text.Json;
using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Domain.Audit;
using HIP.Security.Infrastructure.Persistence;

namespace HIP.Security.Infrastructure.Repositories;

/// <summary>
/// Durable append-only recorder backed by SecurityAuditDbContext.
/// </summary>
public sealed class SqlitePolicyAuditRecorder(SecurityAuditDbContext dbContext) : IPolicyAuditRecorder
{
    public async Task RecordAsync(PolicyAuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        var safeMetadata = new Dictionary<string, string>(auditEvent.Metadata);

        dbContext.PolicyAuditEvents.Add(new PolicyAuditRecordEntity
        {
            EventId = auditEvent.EventId,
            PolicyId = auditEvent.PolicyId,
            Action = auditEvent.Action,
            Outcome = auditEvent.Outcome,
            ReasonCode = auditEvent.ReasonCode,
            OccurredAtUtc = auditEvent.OccurredAtUtc,
            MetadataJson = JsonSerializer.Serialize(safeMetadata),
            AppendedAtUtc = DateTimeOffset.UtcNow
        });

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
