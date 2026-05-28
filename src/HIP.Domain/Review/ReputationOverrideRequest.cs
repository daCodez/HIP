namespace HIP.Domain.Review;

public sealed record ReputationOverrideRequest(
    string OverrideRequestId,
    TargetType TargetType,
    string TargetId,
    int CurrentScore,
    int RequestedScore,
    string Reason,
    string RequestedBy,
    OverrideRequestStatus Status,
    int RequiredApprovalCount,
    IReadOnlyCollection<ApprovalRecord> Approvals,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);
