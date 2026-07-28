using System.Text.RegularExpressions;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Administration;

/// <summary>Applies administrator access changes while preserving an active owner and an append-only audit trail.</summary>
public sealed partial class AdminAccessService(
    IAdminAccessRepository repository,
    IAuditLogService auditLogService,
    TimeProvider timeProvider) : IAdminAccessService
{
    private const int MaximumAssignments = 500;

    public async Task<AdminAccessAssignment?> GetCurrentAssignmentAsync(
        string currentActorId,
        CancellationToken cancellationToken)
    {
        ValidateActorId(currentActorId);
        var directory = await repository.GetAsync(cancellationToken).ConfigureAwait(false);
        return directory?.Assignments.SingleOrDefault(
            item => string.Equals(item.ActorId, currentActorId, StringComparison.Ordinal));
    }
    public async Task<AdminAccessDirectory> GetDirectoryAsync(
        string currentActorId,
        string currentClaimRole,
        CancellationToken cancellationToken)
    {
        ValidateActorId(currentActorId);
        var directory = await repository.GetAsync(cancellationToken).ConfigureAwait(false);
        if (directory is not null)
        {
            return directory;
        }

        if (!string.Equals(currentClaimRole, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase))
        {
            return new AdminAccessDirectory(0, [], timeProvider.GetUtcNow());
        }

        var now = timeProvider.GetUtcNow();
        return new AdminAccessDirectory(
            0,
            [new AdminAccessAssignment(currentActorId, "Initial HIP owner", AdminAccessRoleNames.Owner, AdminAccessStatus.Active, now, now)],
            now);
    }

    public async Task<AdminAccessChangeResult> ChangeAsync(
        string currentActorId,
        string currentClaimRole,
        AdminAccessChangeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!string.Equals(currentClaimRole, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase))
        {
            return Result(AdminAccessChangeStatus.Forbidden, null, "Only an active HIP Owner can manage administrator access.");
        }

        try
        {
            ValidateActorId(currentActorId);
            ValidateRequest(request);
        }
        catch (ArgumentException exception)
        {
            return Result(AdminAccessChangeStatus.Invalid, null, exception.Message);
        }

        var stored = await repository.GetAsync(cancellationToken).ConfigureAwait(false);
        if (stored is not null && !stored.Assignments.Any(item =>
                string.Equals(item.ActorId, currentActorId, StringComparison.Ordinal) && IsActiveOwner(item)))
        {
            return Result(AdminAccessChangeStatus.Forbidden, stored, "Only an active HIP Owner can manage administrator access.");
        }

        var current = stored ?? await GetDirectoryAsync(currentActorId, currentClaimRole, cancellationToken).ConfigureAwait(false);
        if (request.ExpectedVersion != current.Version)
        {
            return Result(AdminAccessChangeStatus.Conflict, current, "Administrator access changed in another session. Refresh and retry.");
        }

        if (string.Equals(request.TargetActorId, currentActorId, StringComparison.Ordinal) &&
            (!string.Equals(request.Role, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase) ||
             request.Status != AdminAccessStatus.Active))
        {
            return Result(AdminAccessChangeStatus.SelfChangeDenied, current, "An Owner cannot demote or disable their own active session.");
        }

        var now = timeProvider.GetUtcNow();
        var existing = current.Assignments.SingleOrDefault(
            item => string.Equals(item.ActorId, request.TargetActorId, StringComparison.Ordinal));
        var changed = existing is null
            ? new AdminAccessAssignment(
                request.TargetActorId,
                request.DisplayLabel.Trim(),
                CanonicalRole(request.Role),
                request.Status,
                now,
                now)
            : existing with
            {
                DisplayLabel = request.DisplayLabel.Trim(),
                Role = CanonicalRole(request.Role),
                Status = request.Status,
                UpdatedAtUtc = now
            };

        var assignments = current.Assignments
            .Where(item => !string.Equals(item.ActorId, changed.ActorId, StringComparison.Ordinal))
            .Append(changed)
            .OrderBy(item => item.DisplayLabel, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.ActorId, StringComparer.Ordinal)
            .ToArray();
        if (assignments.Length > MaximumAssignments)
        {
            return Result(AdminAccessChangeStatus.Invalid, current, "The administrator directory has reached its safe V1 limit.");
        }

        if (!assignments.Any(IsActiveOwner))
        {
            return Result(AdminAccessChangeStatus.LastOwnerRequired, current, "HIP must retain at least one active Owner.");
        }

        var updated = new AdminAccessDirectory(checked(current.Version + 1), assignments, now);
        var audit = auditLogService.CreateEntry(
            currentActorId,
            existing is null ? "Administrator access granted" : "Administrator access changed",
            TargetType.Administrator,
            request.TargetActorId,
            "HIP administrator access was changed after an Owner confirmation.",
            AuditSeverity.Critical,
            metadata: new SortedDictionary<string, string>(StringComparer.Ordinal) { ["reason"] = request.Reason.Trim() },
            actorRole: AdminAccessRoleNames.Owner,
            beforeMetadata: existing is null ? null : AuditState(existing),
            afterMetadata: AuditState(changed));

        var saved = await repository.TrySaveAsync(updated, current.Version, audit, cancellationToken).ConfigureAwait(false);
        return saved
            ? Result(AdminAccessChangeStatus.Saved, updated, "Administrator access saved and audited.")
            : Result(AdminAccessChangeStatus.Conflict, current, "Administrator access changed in another session. Refresh and retry.");
    }

    private static bool IsActiveOwner(AdminAccessAssignment item) =>
        item.Status == AdminAccessStatus.Active &&
        string.Equals(item.Role, AdminAccessRoleNames.Owner, StringComparison.OrdinalIgnoreCase);

    private static IReadOnlyDictionary<string, string> AuditState(AdminAccessAssignment assignment) =>
        new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["role"] = assignment.Role,
            ["status"] = assignment.Status.ToString()
        };

    private static void ValidateRequest(AdminAccessChangeRequest request)
    {
        ValidateActorId(request.TargetActorId);
        if (request.ExpectedVersion < 0)
        {
            throw new ArgumentException("The administrator directory version is invalid.");
        }

        if (string.IsNullOrWhiteSpace(request.DisplayLabel))
        {
            throw new ArgumentException("A privacy-safe operator label is required.");
        }

        var label = request.DisplayLabel.Trim();
        if (label.Length is < 2 or > 80 || label.Contains('@') || label.Any(char.IsControl))
        {
            throw new ArgumentException("Use a 2–80 character operator label without an email address or control characters.");
        }

        if (string.IsNullOrWhiteSpace(request.Role) || !AdminAccessRoleNames.All.Contains(request.Role) || !Enum.IsDefined(request.Status))
        {
            throw new ArgumentException("The requested administrator role or status is invalid.");
        }

        if (string.IsNullOrWhiteSpace(request.Reason))
        {
            throw new ArgumentException("A privacy-safe change reason is required.");
        }

        var reason = request.Reason.Trim();
        if (reason.Length is < 5 or > 500 || reason.Any(char.IsControl))
        {
            throw new ArgumentException("Enter a 5–500 character privacy-safe reason without control characters.");
        }
    }

    private static void ValidateActorId(string actorId)
    {
        if (string.IsNullOrWhiteSpace(actorId) || actorId.Length > 160 || !ActorIdPattern().IsMatch(actorId))
        {
            throw new ArgumentException("A valid privacy-safe HIP actor ID is required.");
        }
    }

    private static string CanonicalRole(string role) =>
        AdminAccessRoleNames.All.Single(item => string.Equals(item, role, StringComparison.OrdinalIgnoreCase));

    private static AdminAccessChangeResult Result(
        AdminAccessChangeStatus status,
        AdminAccessDirectory? directory,
        string message) => new(status, directory, message);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9:._-]{1,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex ActorIdPattern();
}