namespace HIP.Domain.Review;

public sealed record ApprovalRecord(
    string ApprovalId,
    string RequestId,
    string ApprovedBy,
    DateTimeOffset ApprovedAtUtc,
    ApprovalDecision Decision,
    string Reason);
