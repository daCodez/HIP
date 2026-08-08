using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>Privacy-safe event committed with a domain certificate state change.</summary>
public sealed record DomainCertificateAuditEvent(
    string EventId,
    string ActorId,
    string EventType,
    DomainCertificateStatus? PreviousStatus,
    DomainCertificateStatus CurrentStatus,
    string? ReasonCode,
    string? PublicSummary,
    DateTimeOffset OccurredAtUtc);

/// <summary>Validated signed certificate and the reproducibility data required for durable issuance.</summary>
public sealed record HipStoredDomainCertificate(
    string EnrollmentId,
    string OwnerId,
    SignedDomainTrustCertificate Certificate,
    string SignedCertificateJson,
    string CertificateDigest,
    string SourceDecisionDigest,
    DomainCertificateAuditEvent IssuanceEvent,
    DomainCertificateStatus CurrentStatus = DomainCertificateStatus.Active,
    string? ManagedDomainId = null,
    string? OrganizationId = null,
    string? ApplicationId = null,
    string? PublicCertificateNumber = null,
    DomainCertificateIssuanceSnapshot? Snapshot = null);

/// <summary>Outcome of an insert-only certificate issuance write.</summary>
public enum DomainCertificateRepositoryWriteStatus
{
    Created,
    ExistingSame,
    Conflict
}

/// <summary>Insert result with the winning durable certificate when one exists.</summary>
public sealed record DomainCertificateRepositoryWriteResult(
    DomainCertificateRepositoryWriteStatus Status,
    HipStoredDomainCertificate? StoredCertificate = null);

/// <summary>Durable certificate history and public lookup boundary.</summary>
public interface IDomainCertificateRepository
{
    /// <summary>Returns a certificate by its non-secret public identifier.</summary>
    Task<HipStoredDomainCertificate?> GetByIdAsync(
        string certificateId,
        CancellationToken cancellationToken);

    /// <summary>Returns the current certificate for an exact canonical domain.</summary>
    Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(
        string domain,
        CancellationToken cancellationToken);

    /// <summary>Atomically creates a signed certificate and its permanent issuance event.</summary>
    Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
        HipStoredDomainCertificate certificate,
        CancellationToken cancellationToken);
}
