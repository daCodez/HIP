using HIP.Domain.Certificates;

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

/// <summary>Atomic owner enrollment and permanent audit persistence boundary.</summary>
public interface IDomainEnrollmentRepository
{
    /// <summary>Creates an initial enrollment and audit event or reconciles an exact retry.</summary>
    Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
        DomainEnrollmentStartRecord enrollment,
        CancellationToken cancellationToken);
}
