using HIP.Domain.Scoring;

namespace HIP.Domain.Reputation;

public sealed record ReputationProfile(
    ReputationSubjectType SubjectType,
    string SubjectId,
    ScoreValue Score,
    IReadOnlyCollection<ReputationEvent> Events)
{
    public bool HasPermanentRestriction =>
        Events.Any(e => e.EventType is ReputationEventType.ConfirmedMaliciousBehavior or ReputationEventType.RepeatedAbuse);
}
