using FluentValidation;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class ReputationOverrideService(
    IValidator<ReputationOverrideRequest> validator,
    IReputationOverrideRequestRepository repository,
    IAuditLogService auditLogService) : IReputationOverrideService
{
    public ReputationOverrideRequest Request(ReputationOverrideRequest request)
    {
        var now = DateTimeOffset.UtcNow;
        var normalized = request with
        {
            OverrideRequestId = string.IsNullOrWhiteSpace(request.OverrideRequestId) ? $"override-{Guid.NewGuid():N}" : request.OverrideRequestId,
            Status = OverrideRequestStatus.Pending,
            RequiredApprovalCount = CalculateRequiredApprovalCount(request.CurrentScore, request.RequestedScore),
            Approvals = request.Approvals ?? [],
            CreatedAtUtc = request.CreatedAtUtc == default ? now : request.CreatedAtUtc,
            UpdatedAtUtc = now
        };

        validator.ValidateAndThrow(normalized);

        Run(repository.SaveAsync(normalized, CancellationToken.None));

        var metadata = new[]
        {
            KeyValuePair.Create("currentScore", normalized.CurrentScore.ToString()),
            KeyValuePair.Create("requestedScore", normalized.RequestedScore.ToString()),
            KeyValuePair.Create("requiredApprovals", normalized.RequiredApprovalCount.ToString())
        }.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        auditLogService.Write(normalized.RequestedBy, "Reputation override requested", normalized.TargetType, normalized.TargetId, normalized.Reason, AuditSeverity.High, metadata);
        return normalized;
    }

    public IReadOnlyCollection<ReputationOverrideRequest> List() =>
        Run(repository.ListAsync(CancellationToken.None))
            .OrderByDescending(request => request.CreatedAtUtc)
            .ToArray();

    public ReputationOverrideRequest Approve(string overrideRequestId, string approvedBy, string reason)
    {
        var request = Find(overrideRequestId);
        if (request.Approvals.Any(approval => string.Equals(approval.ApprovedBy, approvedBy, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Actor has already recorded a decision for this override request.", nameof(approvedBy));
        }

        var approval = new ApprovalRecord(
            $"approval-{Guid.NewGuid():N}",
            overrideRequestId,
            approvedBy,
            DateTimeOffset.UtcNow,
            ApprovalDecision.Approved,
            reason);

        var approvals = request.Approvals.Append(approval).ToArray();
        var approvedCount = approvals.Count(item => item.Decision == ApprovalDecision.Approved);
        var status = approvedCount >= request.RequiredApprovalCount ? OverrideRequestStatus.Approved : OverrideRequestStatus.Pending;
        var updated = request with
        {
            Approvals = approvals,
            Status = status,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        validator.ValidateAndThrow(updated);
        Run(repository.SaveAsync(updated, CancellationToken.None));
        auditLogService.Write(approvedBy, status == OverrideRequestStatus.Approved ? "Reputation override approved" : "Reputation override approval recorded", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);

        if (status == OverrideRequestStatus.Approved)
        {
            auditLogService.Write(approvedBy, "Manual reputation change applied", updated.TargetType, updated.TargetId, $"Approved score change {updated.CurrentScore} -> {updated.RequestedScore}.", AuditSeverity.Critical);
        }

        return updated;
    }

    public ReputationOverrideRequest Reject(string overrideRequestId, string rejectedBy, string reason)
    {
        var request = Find(overrideRequestId);
        var rejection = new ApprovalRecord(
            $"approval-{Guid.NewGuid():N}",
            overrideRequestId,
            rejectedBy,
            DateTimeOffset.UtcNow,
            ApprovalDecision.Rejected,
            reason);
        var updated = request with
        {
            Approvals = request.Approvals.Append(rejection).ToArray(),
            Status = OverrideRequestStatus.Rejected,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        validator.ValidateAndThrow(updated);
        Run(repository.SaveAsync(updated, CancellationToken.None));
        auditLogService.Write(rejectedBy, "Reputation override rejected", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);
        return updated;
    }

    public int CalculateRequiredApprovalCount(int currentScore, int requestedScore)
    {
        var delta = Math.Abs(requestedScore - currentScore);

        if (requestedScore <= 20 || currentScore <= 40 && requestedScore >= 81 || delta >= 30)
        {
            return 2;
        }

        return 1;
    }

    private ReputationOverrideRequest Find(string overrideRequestId)
    {
        var request = Run(repository.GetAsync(overrideRequestId, CancellationToken.None));
        if (request is null)
        {
            throw new ArgumentException("Reputation override request was not found.", nameof(overrideRequestId));
        }

        return request;
    }

    private static void Run(Task task) =>
        task.GetAwaiter().GetResult();

    private static T Run<T>(Task<T> task) =>
        task.GetAwaiter().GetResult();
}
