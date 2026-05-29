using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public sealed record ReputationFeedbackRequest(
    ReputationSubjectType TargetType,
    string TargetId,
    ReputationEventType EventType,
    ReputationEventSeverity Severity,
    ReporterTrustLevel ReporterTrustLevel,
    string Reason,
    string Platform,
    string? UrlHash = null);
