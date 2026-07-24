using HIP.Domain.Certificates;

namespace HIP.Infrastructure.Persistence.Entities;

/// <summary>Indexed, non-secret state for one domain-owner enrollment.</summary>
public sealed class HipDomainEnrollmentEntity
{
    public required string EnrollmentId { get; set; }
    public required string OwnerId { get; set; }
    public required string Domain { get; set; }
    public DomainEnrollmentStatus Status { get; set; }
    public required string PolicyVersion { get; set; }
    public bool IsCurrent { get; set; } = true;
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public DateTimeOffset? DnsVerifiedAtUtc { get; set; }
    public DateTimeOffset? WebsiteVerifiedAtUtc { get; set; }
    public DateTimeOffset? IdentityCompletedAtUtc { get; set; }
    public DateTimeOffset? SecurityReviewCompletedAtUtc { get; set; }
    public DateTimeOffset? LastMonitoringAtUtc { get; set; }
    public int? CurrentScore { get; set; }
    public int UnresolvedCriticalFindings { get; set; }
    public long AggregateVersion { get; set; }
}

/// <summary>Public and signed fields for one version of a HIP Domain Trust Certificate.</summary>
public sealed class HipDomainCertificateEntity
{
    public required string CertificateId { get; set; }
    public required string EnrollmentId { get; set; }
    public required string OwnerId { get; set; }
    public required string Domain { get; set; }
    public DomainCertificateLevel Level { get; set; }
    public DomainCertificateStatus Status { get; set; }
    public required string PolicyVersion { get; set; }
    public int CertificateVersion { get; set; }
    public bool IsCurrent { get; set; } = true;
    public DateTimeOffset? IssuedAtUtc { get; set; }
    public DateTimeOffset? ExpiresAtUtc { get; set; }
    public DateTimeOffset? LastVerificationAtUtc { get; set; }
    public DateTimeOffset? LastMonitoringAtUtc { get; set; }
    public string? PublicDisplayName { get; set; }
    public string? PublicOrganizationName { get; set; }
    public string? SigningKeyId { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public string? CanonicalPayload { get; set; }
    public string? Signature { get; set; }
    public string? SigningAuthorityId { get; set; }
    public string? VerificationMethodsJson { get; set; }
    public string? SignatureAlgorithmFamily { get; set; }
    public string? SignatureCanonicalization { get; set; }
    public string? RegistrantPublicKeyId { get; set; }
    public string? PublicFindingsSummaryJson { get; set; }
    public string? PublicRiskClassification { get; set; }
    public string? PublicCertificateUrl { get; set; }
    public string? SignedCertificateJson { get; set; }
    public string? CertificateDigest { get; set; }
    public string? SourceDecisionDigest { get; set; }
    public string? RevocationStatusUrl { get; set; }
    public long AggregateVersion { get; set; }
}

/// <summary>Append-only, privacy-safe event in a domain certificate audit trail.</summary>
public sealed class HipDomainCertificateEventEntity
{
    public required string EventId { get; set; }
    public required string EnrollmentId { get; set; }
    public string? CertificateId { get; set; }
    public required string EventType { get; set; }
    public string? PreviousStatus { get; set; }
    public required string CurrentStatus { get; set; }
    public required string ActorId { get; set; }
    public string? ReasonCode { get; set; }
    public string? PublicSummary { get; set; }
    public required string PolicyVersion { get; set; }
    public string? EvidenceDigest { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
}
