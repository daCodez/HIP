using HIP.Domain.Certificates;
using HIP.Domain.Identity;

namespace HIP.Application.Certificates;

/// <summary>Validated initial owner enrollment written together with its audit event.</summary>
public sealed record DomainEnrollmentStartRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DomainEnrollmentStatus Status,
    string PolicyVersion,
    DateTimeOffset CreatedAtUtc,
    string AuditEventId);

/// <summary>Outcome of an idempotent domain enrollment start.</summary>
public enum DomainEnrollmentRepositoryWriteStatus
{
    Created,
    ExistingSame,
    Conflict
}

/// <summary>Enrollment start persistence result.</summary>
public sealed record DomainEnrollmentRepositoryWriteResult(
    DomainEnrollmentRepositoryWriteStatus Status,
    DomainEnrollmentStartRecord? Enrollment = null);

/// <summary>Authoritative successful domain-control verification applied to an owner enrollment.</summary>
public sealed record DomainOwnershipVerificationRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    VerificationMethod Method,
    DateTimeOffset VerifiedAtUtc,
    string AuditEventId);

/// <summary>Outcome of an idempotent enrollment lifecycle transition.</summary>
public enum DomainEnrollmentTransitionWriteStatus
{
    Updated,
    AlreadyApplied,
    NotFound,
    Conflict
}

/// <summary>Enrollment lifecycle persistence result.</summary>
public sealed record DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus Status);

/// <summary>Atomic owner enrollment and permanent audit persistence boundary.</summary>
public interface IDomainEnrollmentRepository
{
    /// <summary>Creates an initial enrollment and audit event or reconciles an exact retry.</summary>
    Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
        DomainEnrollmentStartRecord enrollment,
        CancellationToken cancellationToken);

    /// <summary>Advances a pending enrollment after authoritative domain-control verification.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
        DomainOwnershipVerificationRecord verification,
        CancellationToken cancellationToken);
}
