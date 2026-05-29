namespace HIP.Domain.Reputation;

public sealed record ReputationEvent(
    string EventId,
    ReputationSubjectType TargetType,
    string TargetId,
    ReputationEventType EventType,
    ReputationEventSeverity Severity,
    int ScoreImpact,
    ReporterTrustLevel ReporterTrustLevel,
    string Reason,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    bool IsConfirmed,
    bool IsAccidental);
