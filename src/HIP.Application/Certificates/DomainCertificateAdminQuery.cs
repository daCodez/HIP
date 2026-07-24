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
    DateTimeOffset? LastVerificationAtUtc);

/// <summary>Reads paged cross-owner certificate operations state without owner identifiers.</summary>
public interface IDomainCertificateAdminQuery
{
    Task<IReadOnlyList<AdminDomainCertificateSummary>> ListForAdminAsync(
        int offset,
        int limit,
        CancellationToken cancellationToken);
}
