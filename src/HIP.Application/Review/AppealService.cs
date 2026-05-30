using FluentValidation;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class AppealService(
    IValidator<AppealRequest> validator,
    IAuditLogService auditLogService) : IAppealService
{
    private readonly Dictionary<string, AppealRequest> _appeals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public AppealRequest Submit(AppealRequest appeal)
    {
        var now = DateTimeOffset.UtcNow;
        var normalized = appeal with
        {
            AppealId = string.IsNullOrWhiteSpace(appeal.AppealId) ? $"appeal-{Guid.NewGuid():N}" : appeal.AppealId,
            Status = AppealStatus.Submitted,
            CreatedAtUtc = appeal.CreatedAtUtc == default ? now : appeal.CreatedAtUtc,
            UpdatedAtUtc = now
        };

        validator.ValidateAndThrow(normalized);

        lock (_lock)
        {
            _appeals[normalized.AppealId] = normalized;
        }

        auditLogService.Write("public-appeal", "Appeal submitted", normalized.TargetType, normalized.TargetId, normalized.Reason, AuditSeverity.Medium);
        return normalized;
    }

    public IReadOnlyCollection<AppealRequest> List()
    {
        lock (_lock)
        {
            return _appeals.Values.OrderByDescending(appeal => appeal.CreatedAtUtc).ToArray();
        }
    }

    public AppealRequest? Get(string appealId)
    {
        lock (_lock)
        {
            return _appeals.GetValueOrDefault(appealId);
        }
    }

    public AppealRequest Approve(string appealId, string reviewerId, string reason)
    {
        var updated = Decide(appealId, AppealStatus.Approved, reviewerId, "Approved", reason);
        auditLogService.Write(reviewerId, "Appeal approved", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);
        return updated;
    }

    public AppealRequest Reject(string appealId, string reviewerId, string reason)
    {
        var updated = Decide(appealId, AppealStatus.Rejected, reviewerId, "Rejected", reason);
        auditLogService.Write(reviewerId, "Appeal rejected", updated.TargetType, updated.TargetId, reason, AuditSeverity.High);
        return updated;
    }

    public AppealRequest RequestMoreInfo(string appealId, string reviewerId, string reason)
    {
        var updated = Decide(appealId, AppealStatus.NeedsMoreInfo, reviewerId, "NeedsMoreInfo", reason);
        auditLogService.Write(reviewerId, "Appeal needs more info", updated.TargetType, updated.TargetId, reason, AuditSeverity.Medium);
        return updated;
    }

    private AppealRequest Decide(string appealId, AppealStatus status, string reviewerId, string decision, string reason)
    {
        lock (_lock)
        {
            if (!_appeals.TryGetValue(appealId, out var appeal))
            {
                throw new ArgumentException("Appeal was not found.", nameof(appealId));
            }

            var updated = appeal with
            {
                Status = status,
                ReviewerId = reviewerId,
                Decision = decision,
                DecisionReason = reason,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            validator.ValidateAndThrow(updated);
            _appeals[appealId] = updated;
            return updated;
        }
    }
}
