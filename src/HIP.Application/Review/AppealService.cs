using FluentValidation;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class AppealService(
    IValidator<AppealRequest> validator,
    IAppealRepository repository,
    IAuditLogService auditLogService) : IAppealService
{
    public AppealRequest Submit(AppealRequest appeal) =>
        Run(SubmitAsync(appeal, CancellationToken.None));

    /// <inheritdoc />
    public async Task<AppealRequest> SubmitAsync(AppealRequest appeal, CancellationToken cancellationToken)
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

        await repository.SaveAsync(normalized, cancellationToken).ConfigureAwait(false);

        await auditLogService.WriteAsync(
            "public-appeal",
            "Appeal submitted",
            normalized.TargetType,
            normalized.TargetId,
            normalized.Reason,
            AuditSeverity.Medium,
            cancellationToken).ConfigureAwait(false);
        return normalized;
    }

    public IReadOnlyCollection<AppealRequest> List() =>
        Run(ListAsync(CancellationToken.None));

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken) =>
        (await repository.ListAsync(cancellationToken).ConfigureAwait(false))
            .OrderByDescending(appeal => appeal.CreatedAtUtc)
            .ToArray();

    public AppealRequest? Get(string appealId) =>
        Run(GetAsync(appealId, CancellationToken.None));

    /// <inheritdoc />
    public Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken) =>
        repository.GetAsync(appealId, cancellationToken);

    public AppealRequest Approve(string appealId, string reviewerId, string reason)
    {
        return Run(ApproveAsync(appealId, reviewerId, reason, CancellationToken.None));
    }

    /// <inheritdoc />
    public Task<AppealRequest> ApproveAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        DecideAsync(appealId, AppealStatus.Approved, reviewerId, "Approved", reason, "Appeal approved", AuditSeverity.High, cancellationToken);

    public AppealRequest Reject(string appealId, string reviewerId, string reason)
    {
        return Run(RejectAsync(appealId, reviewerId, reason, CancellationToken.None));
    }

    /// <inheritdoc />
    public Task<AppealRequest> RejectAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        DecideAsync(appealId, AppealStatus.Rejected, reviewerId, "Rejected", reason, "Appeal rejected", AuditSeverity.High, cancellationToken);

    public AppealRequest RequestMoreInfo(string appealId, string reviewerId, string reason)
    {
        return Run(RequestMoreInfoAsync(appealId, reviewerId, reason, CancellationToken.None));
    }

    /// <inheritdoc />
    public Task<AppealRequest> RequestMoreInfoAsync(string appealId, string reviewerId, string reason, CancellationToken cancellationToken) =>
        DecideAsync(appealId, AppealStatus.NeedsMoreInfo, reviewerId, "NeedsMoreInfo", reason, "Appeal needs more info", AuditSeverity.Medium, cancellationToken);

    private async Task<AppealRequest> DecideAsync(
        string appealId,
        AppealStatus status,
        string reviewerId,
        string decision,
        string reason,
        string auditAction,
        AuditSeverity auditSeverity,
        CancellationToken cancellationToken)
    {
        var appeal = await repository.GetAsync(appealId, cancellationToken).ConfigureAwait(false);
        if (appeal is null)
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
        await repository.SaveAsync(updated, cancellationToken).ConfigureAwait(false);
        await auditLogService.WriteAsync(
            reviewerId,
            auditAction,
            updated.TargetType,
            updated.TargetId,
            reason,
            auditSeverity,
            cancellationToken).ConfigureAwait(false);
        return updated;
    }

    private static void Run(Task task) =>
        task.GetAwaiter().GetResult();

    private static T Run<T>(Task<T> task) =>
        task.GetAwaiter().GetResult();
}
