using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.Reputation.Domain;
using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Reputation;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="db">The db value used by this operation.</param>
/// <param name="logger">The logger value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed class DatabaseReputationService(HipDbContext db, ILogger<DatabaseReputationService> logger) : IReputationService
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="identityId">The identityId value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken)
    {
        var breakdown = await GetScoreBreakdownAsync(identityId, cancellationToken);
        return breakdown.Score;
    }

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    public async Task<ReputationScoreBreakdown> GetScoreBreakdownAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId); // validation
        logger.LogDebug("Reputation lookup requested for {IdentityId}", identityId); // logging/security awareness

        var signals = await db.ReputationSignals.AsNoTracking().FirstOrDefaultAsync(x => x.IdentityId == identityId, cancellationToken);
        if (signals is null)
        {
            return new ReputationScoreBreakdown(identityId, ReputationConstants.BaseScore, 0, 0, 0, 0, 0, 0, DateTimeOffset.UtcNow);
        }

        var acceptance = Clamp01(signals.AcceptanceRatio) * ReputationConstants.AcceptanceRatioWeight;
        var feedback = Clamp01(signals.FeedbackScore) * ReputationConstants.FeedbackScoreWeight;
        var trust = Math.Log(1 + Math.Max(0, signals.DaysActive)) * ReputationConstants.TrustOverTimeWeight;

        var rawPenaltyUnits = (signals.AbuseReports * 10) + (signals.AuthFailures * 5) + (signals.SpamFlags * 20);

        var now = DateTimeOffset.UtcNow;
        var eventRows = await db.ReputationEvents.AsNoTracking()
            .Where(x => x.IdentityId == identityId)
            .ToListAsync(cancellationToken);

        var eventPenaltyUnits = eventRows.Sum(x =>
        {
            var baseUnits = x.EventType switch
            {
                "replay_abuse" => ReputationConstants.ReplayAbusePenaltyUnits,
                "policy_blocked" => ReputationConstants.PolicyBlockedPenaltyUnits,
                "replay_benign" => ReputationConstants.ReplayBenignPenaltyUnits,
                _ => 0
            };

            if (baseUnits <= 0)
            {
                return 0d;
            }

            var ageDays = Math.Max(0, (now - x.CreatedAtUtc).TotalDays);
            var decayFactor = Math.Pow(0.5, ageDays / ReputationConstants.EventPenaltyHalfLifeDays);
            return baseUnits * decayFactor;
        });

        var aggregatePenalty = rawPenaltyUnits * ReputationConstants.PenaltyWeight / 100.0;
        var eventPenalty = eventPenaltyUnits * ReputationConstants.PenaltyWeight / 100.0;
        var score = ReputationConstants.BaseScore + acceptance + feedback + trust - aggregatePenalty - eventPenalty;
        var boundedScore = (int)Math.Clamp(Math.Round(score), 0, 100);

        return new ReputationScoreBreakdown(
            IdentityId: identityId,
            Score: boundedScore,
            AcceptanceComponent: acceptance,
            FeedbackComponent: feedback,
            TrustComponent: trust,
            AggregatePenaltyComponent: aggregatePenalty,
            EventPenaltyComponent: eventPenalty,
            EventCount: eventRows.Count,
            ComputedAtUtc: now);
    }

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="identityId">The identityId value used by this operation.</param>
    /// <param name="eventType">The eventType value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task RecordSecurityEventAsync(string identityId, string eventType, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(identityId) || string.IsNullOrWhiteSpace(eventType))
        {
            return;
        }

        var record = await db.ReputationSignals.FirstOrDefaultAsync(x => x.IdentityId == identityId, cancellationToken);
        if (record is null)
        {
            record = new ReputationSignalRecord
            {
                IdentityId = identityId,
                AcceptanceRatio = 0,
                FeedbackScore = 0,
                DaysActive = 0,
                AbuseReports = 0,
                AuthFailures = 0,
                SpamFlags = 0,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            db.ReputationSignals.Add(record);
        }

        switch (eventType)
        {
            case "replay_abuse":
                record.AbuseReports += 1;
                record.SpamFlags += 1;
                break;
            case "replay_benign":
                record.AuthFailures += 0;
                break;
            case "policy_blocked":
                record.AbuseReports += 1;
                break;
        }

        record.UpdatedAtUtc = DateTimeOffset.UtcNow;

        db.ReputationEvents.Add(new ReputationEventRecord
        {
            IdentityId = identityId,
            EventType = eventType,
            CreatedAtUtc = DateTimeOffset.UtcNow
        });

        await db.SaveChangesAsync(cancellationToken);
    }

    private static double Clamp01(double value) => Math.Max(0, Math.Min(1, value));
}
