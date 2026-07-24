using HIP.Domain.Certificates;

namespace HIP.Application.Certificates;

/// <summary>Private, owner-scoped certificate progress assembled from durable indexed state.</summary>
public sealed record OwnerDomainCertificateSummary(
    string EnrollmentId,
    string Domain,
    DomainEnrollmentStatus EnrollmentStatus,
    string PolicyVersion,
    DateTimeOffset CreatedAtUtc,
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

/// <summary>Reads paged domain-certificate progress for exactly one authenticated owner.</summary>
public interface IDomainCertificateOwnerQuery
{
    /// <summary>
    /// Returns current enrollments and certificates owned by the exact server-resolved owner identifier.
    /// </summary>
    Task<IReadOnlyList<OwnerDomainCertificateSummary>> ListForOwnerAsync(
        string ownerId,
        int offset,
        int limit,
        CancellationToken cancellationToken);
}
