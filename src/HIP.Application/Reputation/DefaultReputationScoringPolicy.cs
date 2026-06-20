using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

/// <summary>
/// Default HIP reputation scoring policy for MVP reputation decisions.
/// </summary>
public sealed class DefaultReputationScoringPolicy : IReputationScoringPolicy
{
    /// <summary>
    /// Gets the neutral starting score used before HIP receives privacy-safe reputation events.
    /// </summary>
    public const int NeutralScore = 75;

    /// <summary>
    /// Gets conservative reporter weights so feedback never behaves like raw popularity voting.
    /// </summary>
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

    /// <inheritdoc />
    public int DefaultScore => NeutralScore;

    /// <inheritdoc />
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

    /// <inheritdoc />
    public RiskStatus CalculateStatus(int score) => score switch
    {
        <= 20 => RiskStatus.Dangerous,
        <= 40 => RiskStatus.HighRisk,
        <= 60 => RiskStatus.Caution,
        <= 80 => RiskStatus.ProbablySafe,
        _ => RiskStatus.Trusted
    };

    /// <inheritdoc />
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

    /// <inheritdoc />
    public int DefaultImpact(ReputationEventType eventType, ReputationEventSeverity severity) => eventType switch
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

    /// <inheritdoc />
    public DateTimeOffset? ExpiresAt(ReputationEventType eventType, ReputationEventSeverity severity, DateTimeOffset createdAtUtc)
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

    /// <inheritdoc />
    public bool IsConfirmed(ReputationEventType eventType) =>
        eventType is ReputationEventType.ConfirmedMaliciousBehavior or ReputationEventType.RepeatedAbuse;

    /// <summary>
    /// Applies decay rules while preserving long-term penalties for confirmed dangerous abuse.
    /// </summary>
    /// <param name="reputationEvent">Reputation event being decayed.</param>
    /// <param name="asOfUtc">UTC time used to calculate event age.</param>
    /// <returns>Decayed score impact.</returns>
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

    /// <summary>
    /// Converts event severity into a default reputation impact magnitude.
    /// </summary>
    /// <param name="severity">Severity of the reputation event.</param>
    /// <returns>Positive impact magnitude before event direction is applied.</returns>
    private static int SeverityImpact(ReputationEventSeverity severity) => severity switch
    {
        ReputationEventSeverity.Low => 6,
        ReputationEventSeverity.Medium => 12,
        ReputationEventSeverity.High => 22,
        ReputationEventSeverity.Dangerous => 35,
        ReputationEventSeverity.Critical => 50,
        _ => 0
    };
}
