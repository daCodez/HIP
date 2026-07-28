using HIP.Domain.Audit;

namespace HIP.Application.Administration;

/// <summary>Lifecycle state for an authenticated administrator access request.</summary>
public enum AdminAccessRequestStatus
{
    Pending = 0,
    Denied = 1,
    Withdrawn = 2
}

/// <summary>An encrypted, privacy-minimized request to be considered for HIP administrator access.</summary>
public sealed record AdminAccessRequestRecord(
    string RequestId,
    string ActorId,
    string DisplayLabel,
    string Reason,
    AdminAccessRequestStatus Status,
    long Version,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

/// <summary>User-supplied privacy-safe context for an administrator access request.</summary>
public sealed record AdminAccessRequestSubmission(string DisplayLabel, string Reason);

/// <summary>Possible outcomes when HIP receives or resolves an access request.</summary>
public enum AdminAccessRequestMutationStatus
{
    Saved = 0,
    AlreadyPending = 1,
    AlreadyAssigned = 2,
    Conflict = 3,
    Invalid = 4,
    Forbidden = 5,
    NotFound = 6
}

/// <summary>Result of one fail-closed administrator access-request mutation.</summary>
public sealed record AdminAccessRequestMutationResult(
    AdminAccessRequestMutationStatus Status,
    AdminAccessRequestRecord? Request,
    string Message);

/// <summary>Encrypted persistence boundary for administrator access requests and their audit entries.</summary>
public interface IAdminAccessRequestRepository
{
    Task<AdminAccessRequestRecord?> GetForActorAsync(string actorId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AdminAccessRequestRecord>> ListAsync(CancellationToken cancellationToken);

    Task<bool> TrySaveAsync(
        AdminAccessRequestRecord request,
        long expectedVersion,
        AuditLogEntry auditEntry,
        CancellationToken cancellationToken);
}

/// <summary>Captures the authenticated actor automatically and exposes requests only to active Owners.</summary>
public interface IAdminAccessRequestService
{
    Task<AdminAccessRequestRecord?> GetCurrentAsync(string actorId, CancellationToken cancellationToken);

    Task<AdminAccessRequestMutationResult> SubmitAsync(
        string actorId,
        AdminAccessRequestSubmission submission,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AdminAccessRequestRecord>> ListPendingAsync(
        string currentActorId,
        string currentClaimRole,
        CancellationToken cancellationToken);

    Task<AdminAccessRequestMutationResult> DenyAsync(
        string currentActorId,
        string currentClaimRole,
        string targetActorId,
        long expectedVersion,
        string reason,
        CancellationToken cancellationToken);
}
