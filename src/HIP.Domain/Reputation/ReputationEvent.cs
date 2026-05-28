namespace HIP.Domain.Reputation;

public sealed record ReputationEvent(
    ReputationEventType EventType,
    decimal ReporterTrustWeight,
    DateTimeOffset OccurredAt,
    string Explanation);
