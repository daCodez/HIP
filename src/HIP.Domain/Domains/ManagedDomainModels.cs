namespace HIP.Domain.Domains;

/// <summary>Lifecycle status of a domain registered in the HIP owner portal.</summary>
public enum ManagedDomainStatus
{
    Active,
    ActionRequired,
    Removed
}

/// <summary>Observed DNSSEC state retained on a managed domain security profile.</summary>
public enum DomainDnssecStatus
{
    Unknown,
    Unsupported,
    Disabled,
    Valid,
    Invalid,
    Misconfigured
}

/// <summary>Domain and organization access roles ordered from least to most privileged.</summary>
public enum DomainAccessRole
{
    Viewer,
    SecurityManager,
    DomainManager,
    Administrator,
    Owner
}

/// <summary>A stable domain record shared by single-domain and multi-domain accounts.</summary>
public sealed record ManagedDomain(
    string DomainId,
    string DomainName,
    string OwnerId,
    string? OrganizationId,
    ManagedDomainStatus Status,
    DomainDnssecStatus DnssecStatus,
    string? DnssecDiagnostic,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    long Version);

/// <summary>An optional organization that groups domains and authorized users.</summary>
public sealed record DomainOrganization(
    string OrganizationId,
    string Name,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    long Version);

/// <summary>Access granted to a HIP user across every domain assigned to an organization.</summary>
public sealed record OrganizationDomainMembership(
    string OrganizationId,
    string UserId,
    DomainAccessRole Role,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

/// <summary>Access granted directly to one domain independently of organization membership.</summary>
public sealed record ManagedDomainAccessGrant(
    string DomainId,
    string UserId,
    DomainAccessRole Role,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

