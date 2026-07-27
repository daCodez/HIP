using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>Privacy-safe administrator view of current enrollment and certificate state.</summary>
public sealed record AdminDomainCertificateSummary(
    string EnrollmentId,
    string Domain,
    DomainEnrollmentStatus EnrollmentStatus,
    string PolicyVersion,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? DnsVerifiedAtUtc,
    DateTimeOffset? WebsiteVerifiedAtUtc,
    DateTimeOffset? IdentityCompletedAtUtc,
    DateTimeOffset? SecurityReviewCompletedAtUtc,
    DateTimeOffset? LastMonitoringAtUtc,
    int? CurrentScore,
    int UnresolvedCriticalFindings,
    string? CertificateId,
    DomainCertificateStatus? CertificateStatus,
    DomainCertificateLevel? BadgeLevel,
    DateTimeOffset? IssuedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? LastVerificationAtUtc,
    DomainCertificateApplicationStatus ApplicationStatus = DomainCertificateApplicationStatus.Draft,
    DateTimeOffset? ApplicationSubmittedAtUtc = null,
    DateTimeOffset? ApplicationReviewedAtUtc = null,
    string? ApplicantAttestationDigest = null);

/// <summary>Public-safe certificate application progress for one exact normalized domain.</summary>
public sealed record PublicDomainCertificateProgress(
    string Domain,
    DomainEnrollmentStatus EnrollmentStatus,
    DomainCertificateApplicationStatus ApplicationStatus,
    DateTimeOffset? SecurityReviewCompletedAtUtc,
    int UnresolvedCriticalFindings,
    DomainCertificateStatus? CertificateStatus,
    DomainCertificateLevel? CertificateLevel);
/// <summary>Reads paged cross-owner certificate operations state without owner identifiers.</summary>
public interface IDomainCertificateAdminQuery
{
    Task<IReadOnlyList<AdminDomainCertificateSummary>> ListForAdminAsync(
        int offset,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>Returns only public-safe progress for one exact domain.</summary>
    Task<PublicDomainCertificateProgress?> GetPublicProgressAsync(
        string domain,
        CancellationToken cancellationToken) =>
        Task.FromResult<PublicDomainCertificateProgress?>(null);
}
