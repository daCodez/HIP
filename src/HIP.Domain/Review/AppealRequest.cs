namespace HIP.Domain.Review;

public sealed record AppealRequest(
    string AppealId,
    TargetType TargetType,
    string TargetId,
    string SubmittedByHash,
    string Reason,
    AppealStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string? ReviewerId,
    string? Decision,
    string? DecisionReason,
    IReadOnlyDictionary<string, string> PrivacySafeEvidence);
