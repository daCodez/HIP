using FluentValidation;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class ReviewQueueService(
    IValidator<ReviewItem> validator,
    IAuditLogService auditLogService) : IReviewQueueService
{
    private readonly Dictionary<string, ReviewItem> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public ReviewItem Create(ReviewItem item)
    {
        var now = DateTimeOffset.UtcNow;
        var normalized = item with
        {
            ReviewItemId = string.IsNullOrWhiteSpace(item.ReviewItemId) ? $"review-{Guid.NewGuid():N}" : item.ReviewItemId,
            CreatedAtUtc = item.CreatedAtUtc == default ? now : item.CreatedAtUtc,
            UpdatedAtUtc = now,
            Status = item.Status
        };

        validator.ValidateAndThrow(normalized);

        lock (_lock)
        {
            _items[normalized.ReviewItemId] = normalized;
        }

        auditLogService.Write(normalized.CreatedBy, "Review item created", normalized.TargetType, normalized.TargetId, normalized.Title, AuditSeverity.Medium);
        return normalized;
    }

    public IReadOnlyCollection<ReviewItem> List()
    {
        lock (_lock)
        {
            return _items.Values.OrderByDescending(item => item.CreatedAtUtc).ToArray();
        }
    }

    public ReviewItem? Get(string reviewItemId)
    {
        lock (_lock)
        {
            return _items.GetValueOrDefault(reviewItemId);
        }
    }

    public ReviewItem Assign(string reviewItemId, string assignedTo, string actorId)
    {
        var updated = Update(reviewItemId, item => item with
        {
            AssignedTo = assignedTo,
            Status = ReviewStatus.InReview,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        auditLogService.Write(actorId, "Review item assigned", updated.TargetType, updated.TargetId, $"Assigned to {assignedTo}.", AuditSeverity.Low);
        return updated;
    }

    public ReviewItem UpdateStatus(string reviewItemId, ReviewStatus status, string actorId, string? reason = null)
    {
        var updated = Update(reviewItemId, item => item with
        {
            Status = status,
            DecisionReason = reason ?? item.DecisionReason,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });
        auditLogService.Write(actorId, $"Review item status changed to {status}", updated.TargetType, updated.TargetId, reason ?? updated.Title, AuditSeverity.Medium);
        return updated;
    }

    public ReviewItem Approve(string reviewItemId, string actorId, string reason)
    {
        var updated = Decide(reviewItemId, ReviewStatus.Approved, "Approved", reason);
        auditLogService.Write(actorId, "Review item approved", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);
        return updated;
    }

    public ReviewItem Reject(string reviewItemId, string actorId, string reason)
    {
        var updated = Decide(reviewItemId, ReviewStatus.Rejected, "Rejected", reason);
        auditLogService.Write(actorId, "Review item rejected", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);
        return updated;
    }

    public ReviewItem RequestMoreInfo(string reviewItemId, string actorId, string reason)
    {
        var updated = Decide(reviewItemId, ReviewStatus.NeedsMoreInfo, "NeedsMoreInfo", reason);
        auditLogService.Write(actorId, "Review item needs more info", updated.TargetType, updated.TargetId, reason, AuditSeverity.Medium);
        return updated;
    }

    public ReviewItem Close(string reviewItemId, string actorId, string reason)
    {
        var updated = Decide(reviewItemId, ReviewStatus.Closed, "Closed", reason);
        auditLogService.Write(actorId, "Review item closed", updated.TargetType, updated.TargetId, reason, AuditSeverity.Medium);
        return updated;
    }

    private ReviewItem Decide(string reviewItemId, ReviewStatus status, string decision, string reason) =>
        Update(reviewItemId, item => item with
        {
            Status = status,
            Decision = decision,
            DecisionReason = reason,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        });

    private ReviewItem Update(string reviewItemId, Func<ReviewItem, ReviewItem> update)
    {
        lock (_lock)
        {
            if (!_items.TryGetValue(reviewItemId, out var item))
            {
                throw new ArgumentException("Review item was not found.", nameof(reviewItemId));
            }

            var updated = update(item);
            validator.ValidateAndThrow(updated);
            _items[reviewItemId] = updated;
            return updated;
        }
    }
}
