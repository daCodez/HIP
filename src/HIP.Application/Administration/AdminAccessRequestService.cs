using System.Text.RegularExpressions;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Administration;

/// <summary>Runs the consent-based administrator access-request workflow.</summary>
public sealed partial class AdminAccessRequestService(
    IAdminAccessRequestRepository requestRepository,
    IAdminAccessRepository accessRepository,
    IAuditLogService auditLogService,
    TimeProvider timeProvider) : IAdminAccessRequestService
{
    private const int MaximumPendingRequests = 500;

    public Task<AdminAccessRequestRecord?> GetCurrentAsync(
        string actorId,
        CancellationToken cancellationToken)
    {
        ValidateActorId(actorId);
        return requestRepository.GetForActorAsync(actorId, cancellationToken);
    }

    public async Task<AdminAccessRequestMutationResult> SubmitAsync(
        string actorId,
        AdminAccessRequestSubmission submission,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        try
        {
            ValidateActorId(actorId);
            ValidateLabel(submission.DisplayLabel);
            ValidateReason(submission.Reason);
        }
        catch (ArgumentException exception)
        {
            return Result(AdminAccessRequestMutationStatus.Invalid, null, exception.Message);
        }

        var directory = await accessRepository.GetAsync(cancellationToken).ConfigureAwait(false);
        if (directory?.Assignments.Any(item =>
                string.Equals(item.ActorId, actorId, StringComparison.Ordinal) &&
                item.Status == AdminAccessStatus.Active) == true)
        {
            return Result(AdminAccessRequestMutationStatus.AlreadyAssigned, null, "This HIP identity already has active administrator access.");
        }

        var existing = await requestRepository.GetForActorAsync(actorId, cancellationToken).ConfigureAwait(false);
        if (existing?.Status == AdminAccessRequestStatus.Pending)
        {
            return Result(AdminAccessRequestMutationStatus.AlreadyPending, existing, "Your administrator access request is already pending Owner review.");
        }

        if (existing is not null)
        {
            return Result(
                AdminAccessRequestMutationStatus.Invalid,
                existing,
                "This request has already been resolved. A HIP Owner must initiate any further access change.");
        }

        var pendingCount = (await requestRepository.ListAsync(cancellationToken).ConfigureAwait(false))
            .Count(item => item.Status == AdminAccessRequestStatus.Pending);
        if (pendingCount >= MaximumPendingRequests)
        {
            return Result(AdminAccessRequestMutationStatus.Invalid, null, "HIP cannot accept another access request until an Owner reviews the pending queue.");
        }

        var now = timeProvider.GetUtcNow();
        var request = new AdminAccessRequestRecord(
            Guid.NewGuid().ToString("N"),
            actorId,
            submission.DisplayLabel.Trim(),
            submission.Reason.Trim(),
            AdminAccessRequestStatus.Pending,
            1,
            now,
            now);
        var audit = auditLogService.CreateEntry(
            actorId,
            "Administrator access requested",
            TargetType.Administrator,
            request.RequestId,
            "An authenticated HIP identity requested administrator access.",
            AuditSeverity.Medium,
            actorRole: "AuthenticatedUser",
            afterMetadata: State(request));

        var saved = await requestRepository.TrySaveAsync(request, 0, audit, cancellationToken).ConfigureAwait(false);
        return saved
            ? Result(AdminAccessRequestMutationStatus.Saved, request, "Your request was submitted for Owner review.")
            : Result(AdminAccessRequestMutationStatus.Conflict, null, "Another request was saved for this identity. Refresh to see its status.");
    }

    public async Task<IReadOnlyCollection<AdminAccessRequestRecord>> ListPendingAsync(
        string currentActorId,
        string currentClaimRole,
        CancellationToken cancellationToken)
    {
        if (!await IsActiveOwnerAsync(currentActorId, currentClaimRole, cancellationToken).ConfigureAwait(false))
        {
            return [];
        }

        var assignments = (await accessRepository.GetAsync(cancellationToken).ConfigureAwait(false))?.Assignments ?? [];
        var assignedActors = assignments.Select(item => item.ActorId).ToHashSet(StringComparer.Ordinal);
        return (await requestRepository.ListAsync(cancellationToken).ConfigureAwait(false))
            .Where(item => item.Status == AdminAccessRequestStatus.Pending && !assignedActors.Contains(item.ActorId))
            .OrderBy(item => item.CreatedAtUtc)
            .Take(MaximumPendingRequests)
            .ToArray();
    }

    public async Task<AdminAccessRequestMutationResult> DenyAsync(
        string currentActorId,
        string currentClaimRole,
        string targetActorId,
        long expectedVersion,
        string reason,
        CancellationToken cancellationToken)
    {
        try
        {
            ValidateActorId(currentActorId);
            ValidateActorId(targetActorId);
            ValidateReason(reason);
        }
        catch (ArgumentException exception)
        {
            return Result(AdminAccessRequestMutationStatus.Invalid, null, exception.Message);
        }

        if (!await IsActiveOwnerAsync(currentActorId, currentClaimRole, cancellationToken).ConfigureAwait(false))
        {
            return Result(AdminAccessRequestMutationStatus.Forbidden, null, "Only an active HIP Owner can deny administrator access requests.");
        }

        var existing = await requestRepository.GetForActorAsync(targetActorId, cancellationToken).ConfigureAwait(false);
        if (existing is null || existing.Status != AdminAccessRequestStatus.Pending)
        {
            return Result(AdminAccessRequestMutationStatus.NotFound, existing, "The pending access request no longer exists.");
        }

        if (existing.Version != expectedVersion)
        {
            return Result(AdminAccessRequestMutationStatus.Conflict, existing, "The access request changed in another session. Refresh and retry.");
        }

        var updated = existing with
        {
            Status = AdminAccessRequestStatus.Denied,
            Version = checked(existing.Version + 1),
            UpdatedAtUtc = timeProvider.GetUtcNow()
        };
        var audit = auditLogService.CreateEntry(
            currentActorId,
            "Administrator access request denied",
            TargetType.Administrator,
            existing.RequestId,
            "A HIP Owner denied an administrator access request after confirmation.",
            AuditSeverity.Medium,
            metadata: new SortedDictionary<string, string>(StringComparer.Ordinal) { ["reason"] = reason.Trim() },
            actorRole: AdminAccessRoleNames.Owner,
            beforeMetadata: State(existing),
            afterMetadata: State(updated));
        var saved = await requestRepository.TrySaveAsync(updated, expectedVersion, audit, cancellationToken).ConfigureAwait(false);
        return saved
            ? Result(AdminAccessRequestMutationStatus.Saved, updated, "The access request was denied and audited.")
            : Result(AdminAccessRequestMutationStatus.Conflict, existing, "The access request changed in another session. Refresh and retry.");
    }

    private async Task<bool> IsActiveOwnerAsync(
        string actorId,
        string claimRole,
        CancellationToken cancellationToken)
    {
        ValidateActorId(actorId);
        if (!string.Equals(claimRole, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var directory = await accessRepository.GetAsync(cancellationToken).ConfigureAwait(false);
        return directory is null || directory.Assignments.Any(item =>
            string.Equals(item.ActorId, actorId, StringComparison.Ordinal) &&
            item.Status == AdminAccessStatus.Active &&
            string.Equals(item.Role, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyDictionary<string, string> State(AdminAccessRequestRecord request) =>
        new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["status"] = request.Status.ToString()
        };

    private static void ValidateActorId(string actorId)
    {
        if (string.IsNullOrWhiteSpace(actorId) || actorId.Length > 160 || !ActorIdPattern().IsMatch(actorId))
        {
            throw new ArgumentException("A valid privacy-safe HIP actor ID is required.");
        }
    }

    private static void ValidateLabel(string label)
    {
        if (string.IsNullOrWhiteSpace(label) || label.Trim().Length is < 2 or > 80 ||
            label.Contains('@') || label.Any(char.IsControl))
        {
            throw new ArgumentException("Use a 2–80 character team-facing label without an email address or control characters.");
        }
    }

    private static void ValidateReason(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length is < 5 or > 500 ||
            reason.Any(char.IsControl))
        {
            throw new ArgumentException("Enter a 5–500 character privacy-safe reason without control characters.");
        }
    }

    private static AdminAccessRequestMutationResult Result(
        AdminAccessRequestMutationStatus status,
        AdminAccessRequestRecord? request,
        string message) => new(status, request, message);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9:._-]{1,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex ActorIdPattern();
}
