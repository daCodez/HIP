using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.Reputation.Domain;
using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Reputation;

public sealed class DatabaseReputationService(HipDbContext db, ILogger<DatabaseReputationService> logger) : IReputationService
{
    public async Task<int> GetScoreAsync(string identityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identityId); // validation
        logger.LogDebug("Reputation lookup requested for {IdentityId}", identityId); // logging/security awareness

        var signals = await db.ReputationSignals.AsNoTracking().FirstOrDefaultAsync(x => x.IdentityId == identityId, cancellationToken);
        if (signals is null)
        {
            return ReputationConstants.BaseScore; // safe default
        }

        var acceptance = Clamp01(signals.AcceptanceRatio) * ReputationConstants.AcceptanceRatioWeight;
        var feedback = Clamp01(signals.FeedbackScore) * ReputationConstants.FeedbackScoreWeight;
        var trust = Math.Log(1 + Math.Max(0, signals.DaysActive)) * ReputationConstants.TrustOverTimeWeight;

        var rawPenaltyUnits = (signals.AbuseReports * 10) + (signals.AuthFailures * 5) + (signals.SpamFlags * 20);
        var penalties = rawPenaltyUnits * ReputationConstants.PenaltyWeight / 100.0;

        var score = ReputationConstants.BaseScore + acceptance + feedback + trust - penalties;
        return (int)Math.Clamp(Math.Round(score), 0, 100); // performance awareness: primitive math only
    }

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
        await db.SaveChangesAsync(cancellationToken);
    }

    private static double Clamp01(double value) => Math.Max(0, Math.Min(1, value));
}
