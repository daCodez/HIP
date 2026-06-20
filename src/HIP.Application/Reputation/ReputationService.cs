using HIP.Domain.Reputation;
using HIP.Domain.Risk;

namespace HIP.Application.Reputation;

/// <summary>
/// Coordinates reputation reads and writes while delegating scoring details to a policy object.
/// </summary>
public sealed class ReputationService(
    IReputationEventRepository eventRepository,
    IReputationProfileRepository profileRepository,
    IReputationScoringPolicy scoringPolicy) : IReputationService
{
    /// <summary>
    /// Neutral starting score used before HIP has enough privacy-safe reputation evidence.
    /// </summary>
    public const int DefaultScore = DefaultReputationScoringPolicy.NeutralScore;

    /// <summary>
    /// Creates the service with the default scoring policy for tests or callers that have not moved to dependency injection yet.
    /// </summary>
    /// <param name="eventRepository">Repository used to append privacy-safe reputation events.</param>
    /// <param name="profileRepository">Repository used to store calculated reputation profiles.</param>
    public ReputationService(
        IReputationEventRepository eventRepository,
        IReputationProfileRepository profileRepository)
        : this(eventRepository, profileRepository, new DefaultReputationScoringPolicy())
    {
    }

    /// <summary>
    /// Loads the current reputation profile or returns a neutral in-memory profile when no events exist yet.
    /// </summary>
    /// <param name="targetType">Type of target being scored.</param>
    /// <param name="targetId">Privacy-safe target identifier.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The stored or calculated reputation profile.</returns>
    public async Task<ReputationProfile> GetProfileAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        ValidateTarget(targetId);
        return await profileRepository.GetAsync(targetType, targetId, cancellationToken) ??
            BuildProfile(targetType, targetId, [], DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Stores a reputation event and recalculates the target profile from event history.
    /// </summary>
    /// <param name="reputationEvent">Privacy-safe reputation event to append.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The recalculated reputation profile.</returns>
    public async Task<ReputationProfile> ApplyEventAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken)
    {
        ValidateTarget(reputationEvent.TargetId);
        await eventRepository.AddAsync(NormalizeEvent(reputationEvent), cancellationToken);
        return await RecalculateAsync(reputationEvent.TargetType, reputationEvent.TargetId, cancellationToken);
    }

    /// <summary>
    /// Converts user or admin feedback into a weighted reputation event without storing private message content.
    /// </summary>
    /// <param name="feedback">Feedback request containing only privacy-safe target and reason data.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The recalculated reputation profile.</returns>
    public Task<ReputationProfile> SubmitFeedbackAsync(ReputationFeedbackRequest feedback, CancellationToken cancellationToken)
    {
        ValidateTarget(feedback.TargetId);
        if (string.IsNullOrWhiteSpace(feedback.Reason))
        {
            throw new ArgumentException("Feedback reason is required.", nameof(feedback));
        }

        var scoreImpact = scoringPolicy.DefaultImpact(feedback.EventType, feedback.Severity);
        var createdAtUtc = DateTimeOffset.UtcNow;
        var reputationEvent = new ReputationEvent(
            $"rep-event-{Guid.NewGuid():N}",
            feedback.TargetType,
            feedback.TargetId,
            feedback.EventType,
            feedback.Severity,
            scoreImpact,
            feedback.ReporterTrustLevel,
            feedback.Reason,
            createdAtUtc,
            scoringPolicy.ExpiresAt(feedback.EventType, feedback.Severity, createdAtUtc),
            scoringPolicy.IsConfirmed(feedback.EventType),
            feedback.EventType == ReputationEventType.AccidentalIssue);

        return ApplyEventAsync(reputationEvent, cancellationToken);
    }

    /// <summary>
    /// Rebuilds a reputation profile from stored event history so score changes remain deterministic.
    /// </summary>
    /// <param name="targetType">Type of target being recalculated.</param>
    /// <param name="targetId">Privacy-safe target identifier.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The recalculated and saved profile.</returns>
    public async Task<ReputationProfile> RecalculateAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        ValidateTarget(targetId);
        var events = await eventRepository.ListAsync(targetType, targetId, cancellationToken);
        var profile = BuildProfile(targetType, targetId, events, DateTimeOffset.UtcNow);
        await profileRepository.SaveAsync(profile, cancellationToken);
        return profile;
    }

    /// <summary>
    /// Calculates the current score through the configured scoring policy.
    /// </summary>
    /// <param name="events">Privacy-safe reputation events for one target.</param>
    /// <param name="asOfUtc">UTC time used for decay calculations.</param>
    /// <returns>A clamped 0-100 reputation score.</returns>
    public int CalculateScore(IReadOnlyCollection<ReputationEvent> events, DateTimeOffset asOfUtc) =>
        scoringPolicy.CalculateScore(events, asOfUtc);

    /// <summary>
    /// Maps a score to the user-facing HIP risk status.
    /// </summary>
    /// <param name="score">Calculated 0-100 reputation score.</param>
    /// <returns>Risk status for the score band.</returns>
    public RiskStatus CalculateStatus(int score) => scoringPolicy.CalculateStatus(score);

    /// <summary>
    /// Builds plain-English reputation explanations from the configured scoring policy.
    /// </summary>
    /// <param name="profile">Calculated reputation profile.</param>
    /// <param name="events">Supporting privacy-safe reputation events.</param>
    /// <returns>Plain-English explanations safe for UI/API display.</returns>
    public IReadOnlyCollection<string> Explain(ReputationProfile profile, IReadOnlyCollection<ReputationEvent> events)
    {
        return scoringPolicy.Explain(profile, events);
    }

    /// <summary>
    /// Builds the reputation profile from event history without mutating the event stream.
    /// </summary>
    /// <param name="targetType">Type of target being scored.</param>
    /// <param name="targetId">Privacy-safe target identifier.</param>
    /// <param name="events">Events used to calculate the profile.</param>
    /// <param name="asOfUtc">UTC time used for scoring and profile freshness.</param>
    /// <returns>A calculated reputation profile with explanations.</returns>
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

    /// <summary>
    /// Fills safe defaults for event identifiers, timestamps, and expiry before persistence.
    /// </summary>
    /// <param name="reputationEvent">Event supplied by the caller.</param>
    /// <returns>A normalized reputation event.</returns>
    private ReputationEvent NormalizeEvent(ReputationEvent reputationEvent)
    {
        var now = DateTimeOffset.UtcNow;
        var createdAtUtc = reputationEvent.CreatedAtUtc == default ? now : reputationEvent.CreatedAtUtc;

        return reputationEvent with
        {
            EventId = string.IsNullOrWhiteSpace(reputationEvent.EventId) ? $"rep-event-{Guid.NewGuid():N}" : reputationEvent.EventId,
            CreatedAtUtc = createdAtUtc,
            ExpiresAtUtc = reputationEvent.ExpiresAtUtc ?? scoringPolicy.ExpiresAt(reputationEvent.EventType, reputationEvent.Severity, createdAtUtc)
        };
    }

    /// <summary>
    /// Rejects empty target identifiers before they reach persistence or scoring.
    /// </summary>
    /// <param name="targetId">Privacy-safe target identifier to validate.</param>
    private static void ValidateTarget(string targetId)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            throw new ArgumentException("Target ID is required.", nameof(targetId));
        }
    }
}
