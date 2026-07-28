using HIP.Domain.Audit;

namespace HIP.Application.Administration;

/// <summary>Stable HIP application roles that may be assigned to an authenticated administrator.</summary>
public static class AdminAccessRoleNames
{
    public const string Owner = nameof(Owner);
    public const string Admin = nameof(Admin);
    public const string Moderator = nameof(Moderator);
    public const string Support = nameof(Support);
    public const string ReadOnly = nameof(ReadOnly);

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Owner, Admin, Moderator, Support, ReadOnly
    };
}

/// <summary>Whether an administrator may currently use HIP.</summary>
public enum AdminAccessStatus
{
    Active = 0,
    Disabled = 1
}

/// <summary>One privacy-minimized HIP administrator assignment.</summary>
public sealed record AdminAccessAssignment(
    string ActorId,
    string DisplayLabel,
    string Role,
    AdminAccessStatus Status,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

/// <summary>Versioned administrator directory stored as one encrypted aggregate.</summary>
public sealed record AdminAccessDirectory(
    long Version,
    IReadOnlyCollection<AdminAccessAssignment> Assignments,
    DateTimeOffset UpdatedAtUtc);

/// <summary>Requested create or update of one administrator assignment.</summary>
public sealed record AdminAccessChangeRequest(
    string TargetActorId,
    string DisplayLabel,
    string Role,
    AdminAccessStatus Status,
    long ExpectedVersion,
    string Reason);

public enum AdminAccessChangeStatus
{
    Saved = 0,
    Conflict = 1,
    Invalid = 2,
    LastOwnerRequired = 3,
    SelfChangeDenied = 4,
    Forbidden = 5
}

/// <summary>Result of one fail-closed administrator access mutation.</summary>
public sealed record AdminAccessChangeResult(
    AdminAccessChangeStatus Status,
    AdminAccessDirectory? Directory,
    string Message);

/// <summary>Persistence boundary for the encrypted administrator directory and its audit entry.</summary>
public interface IAdminAccessRepository
{
    Task<AdminAccessDirectory?> GetAsync(CancellationToken cancellationToken);

    Task<bool> TrySaveAsync(
        AdminAccessDirectory directory,
        long expectedVersion,
        AuditLogEntry auditEntry,
        CancellationToken cancellationToken);
}

/// <summary>Manages privacy-safe HIP administrator role assignments.</summary>
public interface IAdminAccessService
{
    Task<AdminAccessAssignment?> GetCurrentAssignmentAsync(
        string currentActorId,
        CancellationToken cancellationToken);

    Task<AdminAccessDirectory> GetDirectoryAsync(
        string currentActorId,
        string currentClaimRole,
        CancellationToken cancellationToken);

    Task<AdminAccessChangeResult> ChangeAsync(
        string currentActorId,
        string currentClaimRole,
        AdminAccessChangeRequest request,
        CancellationToken cancellationToken);
}