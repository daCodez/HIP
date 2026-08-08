using System.Collections.Concurrent;
using HIP.Application.Certificates;
using HIP.Domain.Domains;

namespace HIP.Application.Domains;

/// <summary>Input used to register a domain in the unified owner registry.</summary>
public sealed record RegisterManagedDomainRequest(string Domain, string? OrganizationId = null);

/// <summary>Bounded filters and ordering supported by the domain dashboard query.</summary>
public sealed record ManagedDomainQuery(
    string? Search = null,
    ManagedDomainStatus? Status = null,
    string? OrganizationId = null,
    bool Descending = false);

/// <summary>Authorization-safe domain projection returned to an authenticated member.</summary>
public sealed record ManagedDomainAccessView(
    string DomainId,
    string DomainName,
    string OwnerId,
    string? OrganizationId,
    ManagedDomainStatus Status,
    DomainDnssecStatus DnssecStatus,
    string? DnssecDiagnostic,
    DomainAccessRole AccessRole,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    long Version);

/// <summary>Raised when an authenticated actor lacks the required domain or organization permission.</summary>
public sealed class DomainAccessDeniedException : InvalidOperationException
{
    public DomainAccessDeniedException() : base("The requested domain operation is not available.") { }
}

/// <summary>Persistence boundary for managed domains, organizations, and their access grants.</summary>
public interface IManagedDomainRepository
{
    /// <summary>Finds a managed domain by its stable identifier.</summary>
    Task<ManagedDomain?> GetDomainAsync(string domainId, CancellationToken cancellationToken);
    /// <summary>Finds a managed domain by its canonical DNS name.</summary>
    Task<ManagedDomain?> GetDomainByNameAsync(string domainName, CancellationToken cancellationToken);
    /// <summary>Lists managed domains for authorization-safe application filtering.</summary>
    Task<IReadOnlyCollection<ManagedDomain>> ListDomainsAsync(CancellationToken cancellationToken);
    /// <summary>Adds a new managed domain.</summary>
    Task AddDomainAsync(ManagedDomain domain, CancellationToken cancellationToken);
    /// <summary>Updates a domain when its expected aggregate version still matches.</summary>
    Task UpdateDomainAsync(ManagedDomain domain, long expectedVersion, CancellationToken cancellationToken);
    /// <summary>Finds an organization by its stable identifier.</summary>
    Task<DomainOrganization?> GetOrganizationAsync(string organizationId, CancellationToken cancellationToken);
    /// <summary>Adds a new organization.</summary>
    Task AddOrganizationAsync(DomainOrganization organization, CancellationToken cancellationToken);
    /// <summary>Finds one user's organization membership.</summary>
    Task<OrganizationDomainMembership?> GetOrganizationMembershipAsync(string organizationId, string userId, CancellationToken cancellationToken);
    /// <summary>Adds or changes an organization membership.</summary>
    Task AddOrUpdateOrganizationMembershipAsync(OrganizationDomainMembership membership, CancellationToken cancellationToken);
    /// <summary>Finds one direct domain access grant.</summary>
    Task<ManagedDomainAccessGrant?> GetDomainAccessAsync(string domainId, string userId, CancellationToken cancellationToken);
    /// <summary>Adds or changes a direct domain access grant.</summary>
    Task AddOrUpdateDomainAccessAsync(ManagedDomainAccessGrant grant, CancellationToken cancellationToken);
}

/// <summary>Authorization-safe operations used by the HIP domain owner portal.</summary>
public interface IDomainManagementService
{
    /// <summary>Registers a canonical public domain and makes the actor its owner.</summary>
    Task<ManagedDomainAccessView> RegisterAsync(string actorId, RegisterManagedDomainRequest request, CancellationToken cancellationToken);
    /// <summary>Creates an organization and makes the actor its owner.</summary>
    Task<DomainOrganization> CreateOrganizationAsync(string actorId, string name, CancellationToken cancellationToken);
    /// <summary>Adds or changes an organization member when the actor can manage memberships.</summary>
    Task AddOrganizationMemberAsync(string actorId, string organizationId, string userId, DomainAccessRole role, CancellationToken cancellationToken);
    /// <summary>Returns a domain only when the actor has access, otherwise a uniform null result.</summary>
    Task<ManagedDomainAccessView?> GetAsync(string actorId, string domainId, CancellationToken cancellationToken);
    /// <summary>Lists only domains visible to the actor.</summary>
    Task<IReadOnlyCollection<ManagedDomainAccessView>> ListAsync(string actorId, ManagedDomainQuery query, CancellationToken cancellationToken);
    /// <summary>Transfers permanent domain ownership and removes implicit access from the former owner.</summary>
    Task<ManagedDomainAccessView> TransferOwnershipAsync(string actorId, string domainId, string newOwnerId, CancellationToken cancellationToken);
    /// <summary>Assigns or removes a domain from an organization when both boundaries authorize the actor.</summary>
    Task<ManagedDomainAccessView> AssignOrganizationAsync(string actorId, string domainId, string? organizationId, CancellationToken cancellationToken);
    /// <summary>Updates the domain's DNSSEC security profile.</summary>
    Task<ManagedDomainAccessView> UpdateDnssecAsync(string actorId, string domainId, DomainDnssecStatus status, string? diagnostic, CancellationToken cancellationToken);
}

/// <summary>Centralized role-to-permission mapping for domain and organization operations.</summary>
public static class ManagedDomainAccessPolicy
{
    /// <summary>Returns whether a role can view a domain.</summary>
    public static bool CanRead(DomainAccessRole role) => Enum.IsDefined(role);
    /// <summary>Returns whether a role can manage security profile state.</summary>
    public static bool CanManageSecurity(DomainAccessRole role) => role >= DomainAccessRole.SecurityManager;
    /// <summary>Returns whether a role can change domain configuration.</summary>
    public static bool CanManageDomain(DomainAccessRole role) => role >= DomainAccessRole.DomainManager;
    /// <summary>Returns whether a role can manage organization memberships.</summary>
    public static bool CanManageMembers(DomainAccessRole role) => role >= DomainAccessRole.Administrator;
    /// <summary>Returns whether a role can transfer permanent domain ownership.</summary>
    public static bool CanTransferOwnership(DomainAccessRole role) => role == DomainAccessRole.Owner;
}

/// <summary>Unified domain-owner service for individual and organization-managed domains.</summary>
public sealed class DomainManagementService(
    IManagedDomainRepository repository,
    DomainRegistrationNormalizer domainNormalizer,
    TimeProvider timeProvider) : IDomainManagementService
{
    /// <inheritdoc />
    public async Task<ManagedDomainAccessView> RegisterAsync(
        string actorId,
        RegisterManagedDomainRequest request,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        ArgumentNullException.ThrowIfNull(request);
        var domainName = domainNormalizer.Normalize(request.Domain);
        if (await repository.GetDomainByNameAsync(domainName, cancellationToken).ConfigureAwait(false) is not null)
        {
            throw new InvalidOperationException("This domain is already registered with HIP.");
        }

        var organizationId = NormalizeOptionalId(request.OrganizationId, nameof(request.OrganizationId));
        if (organizationId is not null)
        {
            await RequireOrganizationRoleAsync(actor, organizationId, ManagedDomainAccessPolicy.CanManageDomain, cancellationToken)
                .ConfigureAwait(false);
        }

        var now = timeProvider.GetUtcNow();
        var domain = new ManagedDomain(
            NewId("domain"), domainName, actor, organizationId, ManagedDomainStatus.Active,
            DomainDnssecStatus.Unknown, null, now, now, 1);
        await repository.AddDomainAsync(domain, cancellationToken).ConfigureAwait(false);
        return View(domain, DomainAccessRole.Owner);
    }

    /// <inheritdoc />
    public async Task<DomainOrganization> CreateOrganizationAsync(
        string actorId,
        string name,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        var normalizedName = NormalizeName(name);
        var now = timeProvider.GetUtcNow();
        var organization = new DomainOrganization(NewId("org"), normalizedName, now, now, 1);
        await repository.AddOrganizationAsync(organization, cancellationToken).ConfigureAwait(false);
        await repository.AddOrUpdateOrganizationMembershipAsync(
            new OrganizationDomainMembership(organization.OrganizationId, actor, DomainAccessRole.Owner, now, now),
            cancellationToken).ConfigureAwait(false);
        return organization;
    }

    /// <inheritdoc />
    public async Task AddOrganizationMemberAsync(
        string actorId,
        string organizationId,
        string userId,
        DomainAccessRole role,
        CancellationToken cancellationToken)
    {
        var normalizedOrganizationId = NormalizeId(organizationId, nameof(organizationId));
        await RequireOrganizationRoleAsync(
            NormalizeId(actorId, nameof(actorId)), normalizedOrganizationId,
            ManagedDomainAccessPolicy.CanManageMembers, cancellationToken).ConfigureAwait(false);
        var memberId = NormalizeId(userId, nameof(userId));
        RequireAssignableRole(role);
        var now = timeProvider.GetUtcNow();
        var existing = await repository.GetOrganizationMembershipAsync(normalizedOrganizationId, memberId, cancellationToken)
            .ConfigureAwait(false);
        await repository.AddOrUpdateOrganizationMembershipAsync(
            new OrganizationDomainMembership(normalizedOrganizationId, memberId, role, existing?.CreatedAtUtc ?? now, now),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ManagedDomainAccessView?> GetAsync(
        string actorId,
        string domainId,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        var domain = await repository.GetDomainAsync(NormalizeId(domainId, nameof(domainId)), cancellationToken)
            .ConfigureAwait(false);
        if (domain is null || domain.Status == ManagedDomainStatus.Removed)
        {
            return null;
        }
        var role = await ResolveRoleAsync(actor, domain, cancellationToken).ConfigureAwait(false);
        return role is null ? null : View(domain, role.Value);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<ManagedDomainAccessView>> ListAsync(
        string actorId,
        ManagedDomainQuery query,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        ArgumentNullException.ThrowIfNull(query);
        var search = NormalizeSearch(query.Search);
        var result = new List<ManagedDomainAccessView>();
        foreach (var domain in await repository.ListDomainsAsync(cancellationToken).ConfigureAwait(false))
        {
            if (domain.Status == ManagedDomainStatus.Removed ||
                query.Status is not null && domain.Status != query.Status ||
                query.OrganizationId is not null && domain.OrganizationId != query.OrganizationId ||
                search is not null && !domain.DomainName.Contains(search, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var role = await ResolveRoleAsync(actor, domain, cancellationToken).ConfigureAwait(false);
            if (role is not null)
            {
                result.Add(View(domain, role.Value));
            }
        }
        return (query.Descending
            ? result.OrderByDescending(item => item.DomainName, StringComparer.Ordinal)
            : result.OrderBy(item => item.DomainName, StringComparer.Ordinal)).ToArray();
    }

    /// <inheritdoc />
    public async Task<ManagedDomainAccessView> TransferOwnershipAsync(
        string actorId,
        string domainId,
        string newOwnerId,
        CancellationToken cancellationToken)
    {
        var domain = await RequireDomainAsync(actorId, domainId, ManagedDomainAccessPolicy.CanTransferOwnership, cancellationToken)
            .ConfigureAwait(false);
        var now = timeProvider.GetUtcNow();
        var updated = domain with { OwnerId = NormalizeId(newOwnerId, nameof(newOwnerId)), UpdatedAtUtc = now, Version = domain.Version + 1 };
        await repository.UpdateDomainAsync(updated, domain.Version, cancellationToken).ConfigureAwait(false);
        return View(updated, DomainAccessRole.Owner);
    }

    /// <inheritdoc />
    public async Task<ManagedDomainAccessView> AssignOrganizationAsync(
        string actorId,
        string domainId,
        string? organizationId,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        var domain = await RequireDomainAsync(actor, domainId, ManagedDomainAccessPolicy.CanManageDomain, cancellationToken)
            .ConfigureAwait(false);
        var normalizedOrganizationId = NormalizeOptionalId(organizationId, nameof(organizationId));
        if (normalizedOrganizationId is not null)
        {
            await RequireOrganizationRoleAsync(actor, normalizedOrganizationId, ManagedDomainAccessPolicy.CanManageDomain, cancellationToken)
                .ConfigureAwait(false);
        }
        var updated = domain with { OrganizationId = normalizedOrganizationId, UpdatedAtUtc = timeProvider.GetUtcNow(), Version = domain.Version + 1 };
        await repository.UpdateDomainAsync(updated, domain.Version, cancellationToken).ConfigureAwait(false);
        return View(updated, (await ResolveRoleAsync(actor, updated, cancellationToken).ConfigureAwait(false)) ?? DomainAccessRole.Owner);
    }

    /// <inheritdoc />
    public async Task<ManagedDomainAccessView> UpdateDnssecAsync(
        string actorId,
        string domainId,
        DomainDnssecStatus status,
        string? diagnostic,
        CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }
        var domain = await RequireDomainAsync(actorId, domainId, ManagedDomainAccessPolicy.CanManageSecurity, cancellationToken)
            .ConfigureAwait(false);
        var role = (await ResolveRoleAsync(actorId, domain, cancellationToken).ConfigureAwait(false))!.Value;
        var updated = domain with
        {
            DnssecStatus = status,
            DnssecDiagnostic = NormalizeDiagnostic(diagnostic),
            UpdatedAtUtc = timeProvider.GetUtcNow(),
            Version = domain.Version + 1
        };
        await repository.UpdateDomainAsync(updated, domain.Version, cancellationToken).ConfigureAwait(false);
        return View(updated, role);
    }

    private async Task<ManagedDomain> RequireDomainAsync(
        string actorId,
        string domainId,
        Func<DomainAccessRole, bool> permission,
        CancellationToken cancellationToken)
    {
        var actor = NormalizeId(actorId, nameof(actorId));
        var domain = await repository.GetDomainAsync(NormalizeId(domainId, nameof(domainId)), cancellationToken).ConfigureAwait(false);
        var role = domain is null ? null : await ResolveRoleAsync(actor, domain, cancellationToken).ConfigureAwait(false);
        if (domain is null || domain.Status == ManagedDomainStatus.Removed || role is null || !permission(role.Value))
        {
            throw new DomainAccessDeniedException();
        }
        return domain;
    }

    private async Task RequireOrganizationRoleAsync(
        string actorId,
        string organizationId,
        Func<DomainAccessRole, bool> permission,
        CancellationToken cancellationToken)
    {
        if (await repository.GetOrganizationAsync(organizationId, cancellationToken).ConfigureAwait(false) is null)
        {
            throw new DomainAccessDeniedException();
        }
        var membership = await repository.GetOrganizationMembershipAsync(organizationId, actorId, cancellationToken).ConfigureAwait(false);
        if (membership is null || !permission(membership.Role))
        {
            throw new DomainAccessDeniedException();
        }
    }

    private async Task<DomainAccessRole?> ResolveRoleAsync(string actorId, ManagedDomain domain, CancellationToken cancellationToken)
    {
        if (domain.OwnerId == actorId)
        {
            return DomainAccessRole.Owner;
        }
        var direct = await repository.GetDomainAccessAsync(domain.DomainId, actorId, cancellationToken).ConfigureAwait(false);
        var organization = domain.OrganizationId is null
            ? null
            : await repository.GetOrganizationMembershipAsync(domain.OrganizationId, actorId, cancellationToken).ConfigureAwait(false);
        return direct is null ? organization?.Role : organization is null ? direct.Role : Higher(direct.Role, organization.Role);
    }

    private static DomainAccessRole Higher(DomainAccessRole left, DomainAccessRole right) => left >= right ? left : right;
    private static ManagedDomainAccessView View(ManagedDomain domain, DomainAccessRole role) => new(
        domain.DomainId, domain.DomainName, domain.OwnerId, domain.OrganizationId, domain.Status,
        domain.DnssecStatus, domain.DnssecDiagnostic, role, domain.CreatedAtUtc, domain.UpdatedAtUtc, domain.Version);
    private static string NewId(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static string NormalizeId(string value, string parameter)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length > 256 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("A valid identifier is required.", parameter);
        }
        return normalized;
    }

    private static string? NormalizeOptionalId(string? value, string parameter) =>
        string.IsNullOrWhiteSpace(value) ? null : NormalizeId(value, parameter);
    private static string NormalizeName(string value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length > 200 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("A valid organization name is required.", nameof(value));
        }
        return normalized;
    }
    private static string? NormalizeSearch(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim()[..Math.Min(value.Trim().Length, 253)];
    private static string? NormalizeDiagnostic(string? value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        if (normalized.Length > 500 || normalized.Any(char.IsControl)) throw new ArgumentException("DNSSEC diagnostic is invalid.", nameof(value));
        return normalized;
    }
    private static void RequireAssignableRole(DomainAccessRole role)
    {
        if (!Enum.IsDefined(role) || role == DomainAccessRole.Owner)
        {
            throw new ArgumentException("Owner access is transferred rather than assigned.", nameof(role));
        }
    }
}

/// <summary>Thread-safe development and test repository for managed-domain aggregates.</summary>
public sealed class InMemoryManagedDomainRepository : IManagedDomainRepository
{
    private readonly ConcurrentDictionary<string, ManagedDomain> domains = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> domainIdsByName = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DomainOrganization> organizations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(string OrganizationId, string UserId), OrganizationDomainMembership> organizationMemberships = new();
    private readonly ConcurrentDictionary<(string DomainId, string UserId), ManagedDomainAccessGrant> domainAccess = new();

    /// <inheritdoc />
    public Task<ManagedDomain?> GetDomainAsync(string domainId, CancellationToken cancellationToken) =>
        Task.FromResult(domains.GetValueOrDefault(domainId));
    /// <inheritdoc />
    public Task<ManagedDomain?> GetDomainByNameAsync(string domainName, CancellationToken cancellationToken) =>
        Task.FromResult(domainIdsByName.TryGetValue(domainName, out var id) ? domains.GetValueOrDefault(id) : null);
    /// <inheritdoc />
    public Task<IReadOnlyCollection<ManagedDomain>> ListDomainsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<ManagedDomain>>(domains.Values.ToArray());
    /// <inheritdoc />
    public Task AddDomainAsync(ManagedDomain domain, CancellationToken cancellationToken)
    {
        if (!domainIdsByName.TryAdd(domain.DomainName, domain.DomainId) || !domains.TryAdd(domain.DomainId, domain))
        {
            domainIdsByName.TryRemove(domain.DomainName, out _);
            throw new InvalidOperationException("This domain is already registered with HIP.");
        }
        return Task.CompletedTask;
    }
    /// <inheritdoc />
    public Task UpdateDomainAsync(ManagedDomain domain, long expectedVersion, CancellationToken cancellationToken)
    {
        if (!domains.TryGetValue(domain.DomainId, out var current) || current.Version != expectedVersion ||
            !domains.TryUpdate(domain.DomainId, domain, current))
        {
            throw new InvalidOperationException("The domain changed before the operation completed.");
        }
        return Task.CompletedTask;
    }
    /// <inheritdoc />
    public Task<DomainOrganization?> GetOrganizationAsync(string organizationId, CancellationToken cancellationToken) =>
        Task.FromResult(organizations.GetValueOrDefault(organizationId));
    /// <inheritdoc />
    public Task AddOrganizationAsync(DomainOrganization organization, CancellationToken cancellationToken)
    {
        if (!organizations.TryAdd(organization.OrganizationId, organization)) throw new InvalidOperationException("Organization already exists.");
        return Task.CompletedTask;
    }
    /// <inheritdoc />
    public Task<OrganizationDomainMembership?> GetOrganizationMembershipAsync(string organizationId, string userId, CancellationToken cancellationToken) =>
        Task.FromResult(organizationMemberships.GetValueOrDefault((organizationId, userId)));
    /// <inheritdoc />
    public Task AddOrUpdateOrganizationMembershipAsync(OrganizationDomainMembership membership, CancellationToken cancellationToken)
    {
        organizationMemberships[(membership.OrganizationId, membership.UserId)] = membership;
        return Task.CompletedTask;
    }
    /// <inheritdoc />
    public Task<ManagedDomainAccessGrant?> GetDomainAccessAsync(string domainId, string userId, CancellationToken cancellationToken) =>
        Task.FromResult(domainAccess.GetValueOrDefault((domainId, userId)));
    /// <inheritdoc />
    public Task AddOrUpdateDomainAccessAsync(ManagedDomainAccessGrant grant, CancellationToken cancellationToken)
    {
        domainAccess[(grant.DomainId, grant.UserId)] = grant;
        return Task.CompletedTask;
    }
}
