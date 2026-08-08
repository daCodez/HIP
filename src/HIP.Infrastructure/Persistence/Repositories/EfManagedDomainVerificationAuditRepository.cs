using HIP.Application.Domains;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>EF Core append-only store for managed-domain verification events.</summary>
public sealed class EfManagedDomainVerificationAuditRepository(HipDbContext dbContext)
    : IManagedDomainVerificationAuditRepository
{
    /// <inheritdoc />
    public async Task AppendAsync(ManagedDomainVerificationAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        dbContext.ManagedDomainVerificationEvents.Add(new HipManagedDomainVerificationEventEntity
        {
            EventId = auditEvent.EventId,
            DomainId = auditEvent.DomainId,
            Method = auditEvent.Method,
            EventType = auditEvent.EventType,
            Outcome = auditEvent.Outcome,
            TokenDigest = auditEvent.TokenDigest,
            ChallengeVersion = auditEvent.ChallengeVersion,
            OccurredAtUtc = auditEvent.OccurredAtUtc,
            ChallengeExpiresAtUtc = auditEvent.ChallengeExpiresAtUtc
        });
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<ManagedDomainVerificationAuditEvent>> ListAsync(
        string domainId,
        CancellationToken cancellationToken) =>
        await dbContext.ManagedDomainVerificationEvents.AsNoTracking()
            .Where(item => item.DomainId == domainId)
            .OrderBy(item => item.OccurredAtUtc)
            .Select(item => new ManagedDomainVerificationAuditEvent(
                item.EventId, item.DomainId, item.Method, item.EventType, item.Outcome, item.TokenDigest,
                item.ChallengeVersion, item.OccurredAtUtc, item.ChallengeExpiresAtUtc))
            .ToArrayAsync(cancellationToken);
}
