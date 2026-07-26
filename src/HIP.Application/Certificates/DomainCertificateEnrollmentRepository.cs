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

/// <summary>Minimal private enrollment state used to authorize lifecycle commands.</summary>
public sealed record DomainEnrollmentStateRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DomainEnrollmentStatus Status,
    DateTimeOffset? DnsVerifiedAtUtc,
    DateTimeOffset? WebsiteVerifiedAtUtc,
    DateTimeOffset? IdentityCompletedAtUtc = null,
    string? PublicDisplayName = null,
    string? PublicOrganizationName = null,
    DateTimeOffset? SecurityReviewCompletedAtUtc = null,
    int? CurrentScore = null,
    int UnresolvedCriticalFindings = 0,
    DomainCertificateApplicationStatus ApplicationStatus = DomainCertificateApplicationStatus.Draft,
    DateTimeOffset? ApplicationSubmittedAtUtc = null,
    DateTimeOffset? ApplicationReviewedAtUtc = null,
    string? ApplicantAttestationDigest = null);

/// <summary>Authoritative HTTPS website-control verification applied to an owner enrollment.</summary>
public sealed record DomainWebsiteVerificationRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    VerificationMethod Method,
    DateTimeOffset VerifiedAtUtc,
    string AuditEventId);

/// <summary>Privacy-filtered public profile plus a one-way private security-contact marker.</summary>
public sealed record DomainCertificateIdentityProfileRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    string PublicDisplayName,
    string? PublicOrganizationName,
    string? PublicWebsiteContact,
    string? PublicCountryOrRegion,
    string SecurityContactHash,
    DateTimeOffset CompletedAtUtc,
    string AuditEventId);

/// <summary>Reproducible server-owned certificate security decision and enrollment projection.</summary>
public sealed record DomainCertificateSecurityReviewRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    DomainCertificatePolicyDecision Decision,
    int CurrentScore,
    int UnresolvedCriticalFindings,
    string EvidenceDigest,
    DateTimeOffset ReviewedAtUtc,
    string AuditEventId);

/// <summary>Authenticated applicant declarations bound to the current identity and domain evidence.</summary>
public sealed record DomainCertificateApplicationSubmissionRecord(
    string EnrollmentId,
    string OwnerId,
    string Domain,
    string AttestationVersion,
    string AttestationDigest,
    DateTimeOffset SubmittedAtUtc,
    string AuditEventId);

/// <summary>Authorized application decision stored with a privacy-safe reason and permanent audit event.</summary>
public sealed record DomainCertificateApplicationDecisionRecord(
    string EnrollmentId,
    DomainCertificateApplicationStatus Decision,
    string Reason,
    string ActorId,
    DateTimeOffset DecidedAtUtc,
    string AuditEventId);


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
    /// <summary>Gets the current enrollment only when it belongs to the exact owner and domain.</summary>
    Task<DomainEnrollmentStateRecord?> GetCurrentAsync(
        string ownerId,
        string domain,
        CancellationToken cancellationToken);

    /// <summary>Creates an initial enrollment and audit event or reconciles an exact retry.</summary>
    Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
        DomainEnrollmentStartRecord enrollment,
        CancellationToken cancellationToken);

    /// <summary>Advances a pending enrollment after authoritative domain-control verification.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
        DomainOwnershipVerificationRecord verification,
        CancellationToken cancellationToken);

    /// <summary>Advances a DNS-verified enrollment after challenge-bound HTTPS verification.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(
        DomainWebsiteVerificationRecord verification,
        CancellationToken cancellationToken);

    /// <summary>Stores a privacy-filtered identity profile and its permanent audit event.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(
        DomainCertificateIdentityProfileRecord profile,
        CancellationToken cancellationToken);

    /// <summary>Stores one server-owned security decision, score projection, and permanent audit event.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(
        DomainCertificateSecurityReviewRecord review,
        CancellationToken cancellationToken);

    /// <summary>Stores an authenticated applicant attestation and permanent submission event.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TrySubmitApplicationAsync(
        DomainCertificateApplicationSubmissionRecord submission,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.NotFound));

    /// <summary>Stores an authorized application decision and permanent decision event.</summary>
    Task<DomainEnrollmentTransitionWriteResult> TryDecideApplicationAsync(
        DomainCertificateApplicationDecisionRecord decision,
        CancellationToken cancellationToken) =>
        Task.FromResult(new DomainEnrollmentTransitionWriteResult(DomainEnrollmentTransitionWriteStatus.NotFound));
}
