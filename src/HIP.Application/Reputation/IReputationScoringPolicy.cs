using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

/// <summary>
/// Calculates reputation scores, labels, event defaults, and explanations from privacy-safe reputation events.
/// </summary>
public interface IReputationScoringPolicy
{
    /// <summary>
    /// Gets the neutral starting score used before HIP has reputation evidence.
    /// </summary>
    int DefaultScore { get; }

    /// <summary>
    /// Calculates the current reputation score from historical events.
    /// </summary>
    /// <param name="events">Privacy-safe reputation events for one target.</param>
    /// <param name="asOfUtc">UTC time used for decay calculations.</param>
    /// <returns>A clamped 0-100 reputation score.</returns>
    int CalculateScore(IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc);

    /// <summary>
    /// Maps a reputation score to the risk status shown by HIP.
    /// </summary>
    /// <param name="score">Calculated 0-100 reputation score.</param>
    /// <returns>Risk status for the score band.</returns>
    RiskStatus CalculateStatus(int score);

    /// <summary>
    /// Builds a plain-English explanation from a profile and its supporting events.
    /// </summary>
    /// <param name="profile">Calculated reputation profile.</param>
    /// <param name="events">Supporting privacy-safe events.</param>
    /// <returns>Explanations safe to show in UI and API responses.</returns>
    IReadOnlyCollection<string> Explain(ReputationProfile profile, IReadOnlyCollection<ReputationEvent> events);

    /// <summary>
    /// Calculates the default score impact for a feedback-derived event.
    /// </summary>
    /// <param name="eventType">Type of reputation event.</param>
    /// <param name="severity">Severity of the event.</param>
    /// <returns>Positive or negative score impact.</returns>
    int DefaultImpact(ReputationEventType eventType, ReputationEventSeverity severity);

    /// <summary>
    /// Calculates the default expiry for an event when HIP can safely decay it.
    /// </summary>
    /// <param name="eventType">Type of reputation event.</param>
    /// <param name="severity">Severity of the event.</param>
    /// <param name="createdAtUtc">UTC creation time.</param>
    /// <returns>Expiry timestamp, or null for long-term evidence.</returns>
    DateTimeOffset? ExpiresAt(ReputationEventType eventType, ReputationEventSeverity severity, DateTimeOffset createdAtUtc);

    /// <summary>
    /// Indicates whether the event type is treated as confirmed abuse by default.
    /// </summary>
    /// <param name="eventType">Type of reputation event.</param>
    /// <returns>True when the event should count as confirmed abuse.</returns>
    bool IsConfirmed(ReputationEventType eventType);
}
