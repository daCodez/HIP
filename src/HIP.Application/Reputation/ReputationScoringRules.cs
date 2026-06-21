using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

/// <summary>
/// Maps a reputation event type to its default score impact.
/// </summary>
/// <param name="RuleId">Stable rule identifier used when reviewing reputation defaults.</param>
/// <param name="Matches">Predicate that selects the event type handled by this rule.</param>
/// <param name="CalculateImpact">Function that calculates the impact for the supplied severity.</param>
internal sealed record ReputationEventImpactRule(
    string RuleId,
    Func<ReputationEventType, bool> Matches,
    Func<ReputationEventSeverity, int> CalculateImpact);

/// <summary>
/// Maps a calculated reputation score to a HIP risk status.
/// </summary>
/// <param name="MaximumScore">Highest score included in the band.</param>
/// <param name="Status">Status returned for the score band.</param>
internal sealed record ReputationStatusBand(int MaximumScore, RiskStatus Status);

/// <summary>
/// Represents one deterministic rule used to calculate when a reputation event can expire.
/// </summary>
internal interface IReputationExpiryRule
{
    /// <summary>
    /// Gets the stable rule identifier used when auditing retention behavior.
    /// </summary>
    string RuleId { get; }

    /// <summary>
    /// Determines whether this rule should set expiry for the event type and severity.
    /// </summary>
    /// <param name="eventType">Type of reputation event.</param>
    /// <param name="severity">Severity assigned to the event.</param>
    /// <returns>True when this rule should calculate expiry.</returns>
    bool Matches(ReputationEventType eventType, ReputationEventSeverity severity);

    /// <summary>
    /// Calculates the expiry timestamp for the matching event.
    /// </summary>
    /// <param name="createdAtUtc">UTC creation time of the event.</param>
    /// <returns>Expiry timestamp, or null for long-term evidence.</returns>
    DateTimeOffset? Apply(DateTimeOffset createdAtUtc);
}

/// <summary>
/// Expires low-severity accidental issues after a short retention window.
/// </summary>
internal sealed class AccidentalLowIssueExpiryRule : IReputationExpiryRule
{
    /// <inheritdoc />
    public string RuleId => "accidental-low-issue-expiry";

    /// <inheritdoc />
    public bool Matches(ReputationEventType eventType, ReputationEventSeverity severity) =>
        eventType == ReputationEventType.AccidentalIssue && severity == ReputationEventSeverity.Low;

    /// <inheritdoc />
    public DateTimeOffset? Apply(DateTimeOffset createdAtUtc) => createdAtUtc.AddDays(90);
}

/// <summary>
/// Expires medium-severity events after one year so moderate evidence can age out.
/// </summary>
internal sealed class MediumSeverityExpiryRule : IReputationExpiryRule
{
    /// <inheritdoc />
    public string RuleId => "medium-severity-expiry";

    /// <inheritdoc />
    public bool Matches(ReputationEventType eventType, ReputationEventSeverity severity) =>
        severity == ReputationEventSeverity.Medium;

    /// <inheritdoc />
    public DateTimeOffset? Apply(DateTimeOffset createdAtUtc) => createdAtUtc.AddDays(365);
}

/// <summary>
/// Keeps strong or long-term events without expiry when no safer expiry rule applies.
/// </summary>
internal sealed class NoExpiryRule : IReputationExpiryRule
{
    /// <inheritdoc />
    public string RuleId => "no-expiry";

    /// <inheritdoc />
    public bool Matches(ReputationEventType eventType, ReputationEventSeverity severity) => true;

    /// <inheritdoc />
    public DateTimeOffset? Apply(DateTimeOffset createdAtUtc) => null;
}

/// <summary>
/// Represents one deterministic rule used to convert a reputation event into a decayed score impact.
/// </summary>
internal interface IReputationDecayRule
{
    /// <summary>
    /// Gets the stable rule identifier used when auditing reputation scoring behavior.
    /// </summary>
    string RuleId { get; }

    /// <summary>
    /// Determines whether this rule should handle the reputation event.
    /// </summary>
    /// <param name="reputationEvent">Privacy-safe reputation event being scored.</param>
    /// <param name="asOfUtc">UTC time used to calculate event age.</param>
    /// <returns>True when the rule should produce the decayed impact.</returns>
    bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc);

    /// <summary>
    /// Calculates the decayed score impact for the matching event.
    /// </summary>
    /// <param name="reputationEvent">Privacy-safe reputation event being scored.</param>
    /// <param name="asOfUtc">UTC time used to calculate event age.</param>
    /// <returns>Decayed score impact before reporter weighting.</returns>
    decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc);
}

/// <summary>
/// Removes expired low-risk accidental issues from scoring.
/// </summary>
internal sealed class ExpiredAccidentalIssueDecayRule : IReputationDecayRule
{
    /// <inheritdoc />
    public string RuleId => "expired-accidental-low-issue";

    /// <inheritdoc />
    public bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) =>
        reputationEvent.ExpiresAtUtc.HasValue &&
        reputationEvent.ExpiresAtUtc.Value <= asOfUtc &&
        reputationEvent.IsAccidental &&
        reputationEvent.Severity == ReputationEventSeverity.Low;

    /// <inheritdoc />
    public decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) => 0m;
}

/// <summary>
/// Keeps a permanent floor for confirmed dangerous abuse so serious evidence cannot disappear with age alone.
/// </summary>
internal sealed class ConfirmedDangerousAbuseDecayRule : IReputationDecayRule
{
    /// <inheritdoc />
    public string RuleId => "confirmed-dangerous-abuse-floor";

    /// <inheritdoc />
    public bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) =>
        reputationEvent.IsConfirmed &&
        reputationEvent.Severity is ReputationEventSeverity.Dangerous or ReputationEventSeverity.Critical;

    /// <inheritdoc />
    public decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc)
    {
        var ageDays = ReputationScoringMath.AgeDays(reputationEvent, asOfUtc);
        var floor = reputationEvent.ScoreImpact * 0.5m;
        var decayed = reputationEvent.ScoreImpact * (decimal)Math.Pow(0.98, ageDays / 30d);
        return Math.Min(decayed, floor);
    }
}

/// <summary>
/// Slowly decays medium-severity events while preserving their influence for near-term reputation decisions.
/// </summary>
internal sealed class MediumSeverityDecayRule : IReputationDecayRule
{
    /// <inheritdoc />
    public string RuleId => "medium-severity-decay";

    /// <inheritdoc />
    public bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) =>
        reputationEvent.Severity == ReputationEventSeverity.Medium;

    /// <inheritdoc />
    public decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc)
    {
        var ageDays = ReputationScoringMath.AgeDays(reputationEvent, asOfUtc);
        return reputationEvent.ScoreImpact * (decimal)Math.Pow(0.95, ageDays / 30d);
    }
}

/// <summary>
/// Quickly decays weak or accidental events so reputation cannot be permanently harmed by low-quality signals.
/// </summary>
internal sealed class LowConfidenceEventDecayRule : IReputationDecayRule
{
    /// <inheritdoc />
    public string RuleId => "low-confidence-event-decay";

    /// <inheritdoc />
    public bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) =>
        reputationEvent.IsAccidental || reputationEvent.Severity == ReputationEventSeverity.Low;

    /// <inheritdoc />
    public decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc)
    {
        var ageDays = ReputationScoringMath.AgeDays(reputationEvent, asOfUtc);
        return reputationEvent.ScoreImpact * (decimal)Math.Pow(0.80, ageDays / 30d);
    }
}

/// <summary>
/// Leaves strong recent events unchanged when no decay rule is safer to apply.
/// </summary>
internal sealed class NoDecayRule : IReputationDecayRule
{
    /// <inheritdoc />
    public string RuleId => "no-decay";

    /// <inheritdoc />
    public bool Matches(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) => true;

    /// <inheritdoc />
    public decimal Apply(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) => reputationEvent.ScoreImpact;
}

/// <summary>
/// Shared math helpers for reputation scoring rules.
/// </summary>
internal static class ReputationScoringMath
{
    /// <summary>
    /// Calculates non-negative event age in days to protect scoring from clock skew.
    /// </summary>
    /// <param name="reputationEvent">Reputation event being scored.</param>
    /// <param name="asOfUtc">UTC time used for the scoring calculation.</param>
    /// <returns>Event age in days, never below zero.</returns>
    public static double AgeDays(ReputationEvent reputationEvent, DateTimeOffset asOfUtc) =>
        Math.Max(0, (asOfUtc - reputationEvent.CreatedAtUtc).TotalDays);
}
