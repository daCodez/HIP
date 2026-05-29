using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

public sealed class ReputationService(
    IReputationEventRepository eventRepository,
    IReputationProfileRepository profileRepository) : IReputationService
{
    public const int DefaultScore = 75;

    public static readonly IReadOnlyDictionary<ReporterTrustLevel, decimal> ReporterWeights =
        new Dictionary<ReporterTrustLevel, decimal>
        {
            [ReporterTrustLevel.Anonymous] = 0.25m,
            [ReporterTrustLevel.Verified] = 0.50m,
            [ReporterTrustLevel.Trusted] = 0.80m,
            [ReporterTrustLevel.Moderator] = 1.00m,
            [ReporterTrustLevel.Admin] = 1.00m,
            [ReporterTrustLevel.KnownFalseReporter] = 0.05m
        };

    public async Task<ReputationProfile> GetProfileAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        ValidateTarget(targetId);
        return await profileRepository.GetAsync(targetType, targetId, cancellationToken) ??
            BuildProfile(targetType, targetId, [], DateTimeOffset.UtcNow);
    }

    public async Task<ReputationProfile> ApplyEventAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken)
    {
        ValidateTarget(reputationEvent.TargetId);
        await eventRepository.AddAsync(NormalizeEvent(reputationEvent), cancellationToken);
        return await RecalculateAsync(reputationEvent.TargetType, reputationEvent.TargetId, cancellationToken);
    }

    public Task<ReputationProfile> SubmitFeedbackAsync(ReputationFeedbackRequest feedback, CancellationToken cancellationToken)
    {
        ValidateTarget(feedback.TargetId);
        if (string.IsNullOrWhiteSpace(feedback.Reason))
        {
            throw new ArgumentException("Feedback reason is required.", nameof(feedback));
        }

        var scoreImpact = DefaultImpact(feedback.EventType, feedback.Severity);
        var reputationEvent = new ReputationEvent(
            $"rep-event-{Guid.NewGuid():N}",
            feedback.TargetType,
            feedback.TargetId,
            feedback.EventType,
            feedback.Severity,
            scoreImpact,
            feedback.ReporterTrustLevel,
            feedback.Reason,
            DateTimeOffset.UtcNow,
            ExpiresAt(feedback.EventType, feedback.Severity, DateTimeOffset.UtcNow),
            IsConfirmed(feedback.EventType),
            feedback.EventType == ReputationEventType.AccidentalIssue);

        return ApplyEventAsync(reputationEvent, cancellationToken);
    }

    public async Task<ReputationProfile> RecalculateAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        ValidateTarget(targetId);
        var events = await eventRepository.ListAsync(targetType, targetId, cancellationToken);
        var profile = BuildProfile(targetType, targetId, events, DateTimeOffset.UtcNow);
        await profileRepository.SaveAsync(profile, cancellationToken);
        return profile;
    }

    public int CalculateScore(IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc)
    {
        var score = DefaultScore;
        var abuseCount = 0;

        foreach (var reputationEvent in events.OrderBy(item => item.CreatedAtUtc))
        {
            var decayedImpact = ApplyDecay(reputationEvent, asOfUtc);
            if (reputationEvent.EventType is ReputationEventType.RepeatedAbuse or ReputationEventType.ConfirmedMaliciousBehavior)
            {
                abuseCount++;
            }

            var repeatedAbuseMultiplier = abuseCount > 1 && decayedImpact < 0
                ? 1m + Math.Min((abuseCount - 1) * 0.25m, 1m)
                : 1m;

            var weightedImpact = decayedImpact * ReporterWeights[reputationEvent.ReporterTrustLevel] * repeatedAbuseMultiplier;
            score += (int)Math.Round(weightedImpact, MidpointRounding.AwayFromZero);
        }

        return Math.Clamp(score, 0, 100);
    }

    public RiskStatus CalculateStatus(int score) => score switch
    {
        <= 20 => RiskStatus.Dangerous,
        <= 40 => RiskStatus.HighRisk,
        <= 60 => RiskStatus.Caution,
        <= 80 => RiskStatus.ProbablySafe,
        _ => RiskStatus.Trusted
    };

    public IReadOnlyCollection<string> Explain(ReputationProfile profile, IReadOnlyCollection<ReputationEvent> events)
    {
        if (events.Count == 0)
        {
            return [$"{profile.TargetType} reputation starts at {DefaultScore}/100 until HIP receives privacy-safe trust signals."];
        }

        var explanations = new List<string>
        {
            $"{profile.TargetType} reputation is {profile.CurrentScore}/100 because HIP evaluated {events.Count} privacy-safe reputation event(s)."
        };

        if (events.Any(item => item.ScoreImpact < 0 &&
            item.ReporterTrustLevel is ReporterTrustLevel.Trusted or ReporterTrustLevel.Moderator or ReporterTrustLevel.Admin))
        {
            explanations.Add($"{profile.TargetType} score lowered because trusted reporters submitted risk feedback.");
        }

        if (profile.ConfirmedAbuseCount > 0)
        {
            explanations.Add("Confirmed malicious behavior remains long-term and does not fully decay.");
        }

        if (profile.AccidentalIssueCount > 0)
        {
            explanations.Add("Accidental or low-risk issues can fade over time.");
        }

        if (events.Count(item => item.EventType is ReputationEventType.RepeatedAbuse or ReputationEventType.ConfirmedMaliciousBehavior) > 1)
        {
            explanations.Add("Repeated intentional abuse created a stronger penalty.");
        }

        return explanations;
    }

    private ReputationProfile BuildProfile(ReputationSubjectType targetType, string targetId, IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc)
    {
        var score = CalculateScore(events, asOfUtc);
        var profile = new ReputationProfile(
            $"rep-{targetType}-{targetId}".ToLowerInvariant(),
            targetType,
            targetId,
            score,
            CalculateStatus(score),
            events.Count,
            events.Count(item => item.IsConfirmed),
            events.Count(item => item.IsAccidental),
            asOfUtc,
            []);

        return profile with { Explanations = Explain(profile, events) };
    }

    private static ReputationEvent NormalizeEvent(ReputationEvent reputationEvent)
    {
        var now = DateTimeOffset.UtcNow;
        return reputationEvent with
        {
            EventId = string.IsNullOrWhiteSpace(reputationEvent.EventId) ? $"rep-event-{Guid.NewGuid():N}" : reputationEvent.EventId,
            CreatedAtUtc = reputationEvent.CreatedAtUtc == default ? now : reputationEvent.CreatedAtUtc,
            ExpiresAtUtc = reputationEvent.ExpiresAtUtc ?? ExpiresAt(reputationEvent.EventType, reputationEvent.Severity, reputationEvent.CreatedAtUtc == default ? now : reputationEvent.CreatedAtUtc)
        };
    }

    private static decimal ApplyDecay(ReputationEvent reputationEvent, DateTimeOffset asOfUtc)
    {
        if (reputationEvent.ExpiresAtUtc.HasValue && reputationEvent.ExpiresAtUtc.Value <= asOfUtc &&
            reputationEvent.IsAccidental && reputationEvent.Severity == ReputationEventSeverity.Low)
        {
            return 0m;
        }

        var ageDays = Math.Max(0, (asOfUtc - reputationEvent.CreatedAtUtc).TotalDays);

        if (reputationEvent.IsConfirmed && reputationEvent.Severity is ReputationEventSeverity.Dangerous or ReputationEventSeverity.Critical)
        {
            var floor = reputationEvent.ScoreImpact * 0.5m;
            var decayed = reputationEvent.ScoreImpact * (decimal)Math.Pow(0.98, ageDays / 30d);
            return Math.Min(decayed, floor);
        }

        if (reputationEvent.Severity == ReputationEventSeverity.Medium)
        {
            return reputationEvent.ScoreImpact * (decimal)Math.Pow(0.95, ageDays / 30d);
        }

        if (reputationEvent.IsAccidental || reputationEvent.Severity == ReputationEventSeverity.Low)
        {
            return reputationEvent.ScoreImpact * (decimal)Math.Pow(0.80, ageDays / 30d);
        }

        return reputationEvent.ScoreImpact;
    }

    private static int DefaultImpact(ReputationEventType eventType, ReputationEventSeverity severity) => eventType switch
    {
        ReputationEventType.PositiveReport => severity == ReputationEventSeverity.Low ? 4 : 8,
        ReputationEventType.FalsePositiveCorrection => 10,
        ReputationEventType.ManualCorrection => 6,
        ReputationEventType.AccidentalIssue => -SeverityImpact(severity) / 2,
        ReputationEventType.SuspiciousReport => -SeverityImpact(severity),
        ReputationEventType.RepeatedAbuse => -SeverityImpact(severity) - 8,
        ReputationEventType.ConfirmedMaliciousBehavior => -SeverityImpact(severity) - 15,
        _ => 0
    };

    private static int SeverityImpact(ReputationEventSeverity severity) => severity switch
    {
        ReputationEventSeverity.Low => 6,
        ReputationEventSeverity.Medium => 12,
        ReputationEventSeverity.High => 22,
        ReputationEventSeverity.Dangerous => 35,
        ReputationEventSeverity.Critical => 50,
        _ => 0
    };

    private static DateTimeOffset? ExpiresAt(ReputationEventType eventType, ReputationEventSeverity severity, DateTimeOffset createdAtUtc)
    {
        if (eventType == ReputationEventType.AccidentalIssue && severity == ReputationEventSeverity.Low)
        {
            return createdAtUtc.AddDays(90);
        }

        if (severity == ReputationEventSeverity.Medium)
        {
            return createdAtUtc.AddDays(365);
        }

        return null;
    }

    private static bool IsConfirmed(ReputationEventType eventType) =>
        eventType is ReputationEventType.ConfirmedMaliciousBehavior or ReputationEventType.RepeatedAbuse;

    private static void ValidateTarget(string targetId)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            throw new ArgumentException("Target ID is required.", nameof(targetId));
        }
    }
}
