namespace HIP.Security.Domain.Approvals;

public sealed record PolicyApprovalMetadata(
    string AuthorId,
    string ReviewerId,
    string ApproverId,
    string? ChangeTicket,
    DateTimeOffset ApprovedAtUtc);
