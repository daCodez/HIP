using HIP.Domain.Domains;

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
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
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
