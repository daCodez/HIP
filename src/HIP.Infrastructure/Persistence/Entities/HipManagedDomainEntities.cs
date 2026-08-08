using HIP.Domain.Domains;
using HIP.Domain.Identity;
using HIP.Domain.Certificates;

namespace HIP.Infrastructure.Persistence.Entities;

/// <summary>Stable, queryable domain record shared by individual and organization accounts.</summary>
public sealed class HipManagedDomainEntity
{
    public required string DomainId { get; set; }
    public required string DomainName { get; set; }
    public required string OwnerId { get; set; }
    public string? OrganizationId { get; set; }
    public ManagedDomainStatus Status { get; set; }
    public DomainDnssecStatus DnssecStatus { get; set; }
    public string? DnssecDiagnostic { get; set; }
    public ManagedDomainVerificationStatus VerificationStatus { get; set; }
    public VerificationMethod? VerificationMethod { get; set; }
    public DateTimeOffset? OwnershipVerifiedAtUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public long Version { get; set; }
}

/// <summary>Append-only privacy-safe managed-domain verification history.</summary>
public sealed class HipManagedDomainVerificationEventEntity
{
    public required string EventId { get; set; }
    public required string DomainId { get; set; }
    public VerificationMethod Method { get; set; }
    public required string EventType { get; set; }
    public DomainVerificationAttemptOutcome Outcome { get; set; }
    public required string TokenDigest { get; set; }
    public int ChallengeVersion { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    public DateTimeOffset? ChallengeExpiresAtUtc { get; set; }
}

/// <summary>One immutable-identity, history-preserving managed-domain certificate application.</summary>
public sealed class HipManagedDomainCertificateApplicationEntity
{
    public required string ApplicationId { get; set; }
    public required string DomainId { get; set; }
    public required string DomainName { get; set; }
    public DomainCertificateLevel RequestedLevel { get; set; }
    public required string ApplicantId { get; set; }
    public string? OrganizationId { get; set; }
    public DomainCertificateApplicationStatus Status { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset? SubmittedAtUtc { get; set; }
    public string? EligibilityJson { get; set; }
    public required string SecurityFindingsJson { get; set; }
    public required string RequiredRemediationJson { get; set; }
    public string? ReviewerId { get; set; }
    public string? ReviewerNotes { get; set; }
    public string? Decision { get; set; }
    public DateTimeOffset? DecisionAtUtc { get; set; }
    public long Version { get; set; }
}

/// <summary>Organization that can group managed domains and memberships.</summary>
public sealed class HipDomainOrganizationEntity
{
    public required string OrganizationId { get; set; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public long Version { get; set; }
}

/// <summary>One user's organization-wide managed-domain access.</summary>
public sealed class HipOrganizationMembershipEntity
{
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    public DomainAccessRole Role { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}

/// <summary>One user's direct access to a single managed domain.</summary>
public sealed class HipManagedDomainAccessEntity
{
    public required string DomainId { get; set; }
    public required string UserId { get; set; }
    public DomainAccessRole Role { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
