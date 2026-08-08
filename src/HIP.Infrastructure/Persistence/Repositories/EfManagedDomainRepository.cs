using HIP.Application.Domains;
using HIP.Domain.Domains;
using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>EF Core persistence for managed domains, organizations, memberships, and direct grants.</summary>
public sealed class EfManagedDomainRepository(HipDbContext dbContext) : IManagedDomainRepository
{
    public async Task<ManagedDomain?> GetDomainAsync(string domainId, CancellationToken cancellationToken) =>
        ToDomain(await dbContext.ManagedDomains.AsNoTracking().SingleOrDefaultAsync(item => item.DomainId == domainId, cancellationToken));

    public async Task<ManagedDomain?> GetDomainByNameAsync(string domainName, CancellationToken cancellationToken) =>
        ToDomain(await dbContext.ManagedDomains.AsNoTracking().SingleOrDefaultAsync(item => item.DomainName == domainName, cancellationToken));

    public async Task<IReadOnlyCollection<ManagedDomain>> ListDomainsAsync(CancellationToken cancellationToken) =>
        (await dbContext.ManagedDomains.AsNoTracking().ToListAsync(cancellationToken)).Select(ToDomainRequired).ToArray();

    public async Task AddDomainAsync(ManagedDomain domain, CancellationToken cancellationToken)
    {
        dbContext.ManagedDomains.Add(ToEntity(domain));
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateDomainAsync(ManagedDomain domain, long expectedVersion, CancellationToken cancellationToken)
    {
        var entity = ToEntity(domain);
        dbContext.ManagedDomains.Attach(entity);
        dbContext.Entry(entity).Property(item => item.Version).OriginalValue = expectedVersion;
        dbContext.Entry(entity).State = EntityState.Modified;
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            throw new InvalidOperationException("The domain changed before the operation completed.", exception);
        }
    }

    public async Task<DomainOrganization?> GetOrganizationAsync(string organizationId, CancellationToken cancellationToken) =>
        ToOrganization(await dbContext.DomainOrganizations.AsNoTracking().SingleOrDefaultAsync(item => item.OrganizationId == organizationId, cancellationToken));

    public async Task AddOrganizationAsync(DomainOrganization organization, CancellationToken cancellationToken)
    {
        dbContext.DomainOrganizations.Add(new HipDomainOrganizationEntity
        {
            OrganizationId = organization.OrganizationId, Name = organization.Name,
            CreatedAtUtc = organization.CreatedAtUtc, UpdatedAtUtc = organization.UpdatedAtUtc, Version = organization.Version
        });
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<OrganizationDomainMembership?> GetOrganizationMembershipAsync(string organizationId, string userId, CancellationToken cancellationToken)
    {
        var entity = await dbContext.OrganizationMemberships.AsNoTracking()
            .SingleOrDefaultAsync(item => item.OrganizationId == organizationId && item.UserId == userId, cancellationToken);
        return entity is null ? null : new(entity.OrganizationId, entity.UserId, entity.Role, entity.CreatedAtUtc, entity.UpdatedAtUtc);
    }

    public async Task AddOrUpdateOrganizationMembershipAsync(OrganizationDomainMembership membership, CancellationToken cancellationToken)
    {
        var entity = await dbContext.OrganizationMemberships
            .SingleOrDefaultAsync(item => item.OrganizationId == membership.OrganizationId && item.UserId == membership.UserId, cancellationToken);
        if (entity is null)
        {
            dbContext.OrganizationMemberships.Add(new HipOrganizationMembershipEntity
            {
                OrganizationId = membership.OrganizationId, UserId = membership.UserId, Role = membership.Role,
                CreatedAtUtc = membership.CreatedAtUtc, UpdatedAtUtc = membership.UpdatedAtUtc
            });
        }
        else
        {
            entity.Role = membership.Role;
            entity.UpdatedAtUtc = membership.UpdatedAtUtc;
        }
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<ManagedDomainAccessGrant?> GetDomainAccessAsync(string domainId, string userId, CancellationToken cancellationToken)
    {
        var entity = await dbContext.ManagedDomainAccess.AsNoTracking()
            .SingleOrDefaultAsync(item => item.DomainId == domainId && item.UserId == userId, cancellationToken);
        return entity is null ? null : new(entity.DomainId, entity.UserId, entity.Role, entity.CreatedAtUtc, entity.UpdatedAtUtc);
    }

    public async Task AddOrUpdateDomainAccessAsync(ManagedDomainAccessGrant grant, CancellationToken cancellationToken)
    {
        var entity = await dbContext.ManagedDomainAccess
            .SingleOrDefaultAsync(item => item.DomainId == grant.DomainId && item.UserId == grant.UserId, cancellationToken);
        if (entity is null)
        {
            dbContext.ManagedDomainAccess.Add(new HipManagedDomainAccessEntity
            {
                DomainId = grant.DomainId, UserId = grant.UserId, Role = grant.Role,
                CreatedAtUtc = grant.CreatedAtUtc, UpdatedAtUtc = grant.UpdatedAtUtc
            });
        }
        else
        {
            entity.Role = grant.Role;
            entity.UpdatedAtUtc = grant.UpdatedAtUtc;
        }
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static ManagedDomain? ToDomain(HipManagedDomainEntity? entity) => entity is null ? null : ToDomainRequired(entity);
    private static ManagedDomain ToDomainRequired(HipManagedDomainEntity entity) => new(
        entity.DomainId, entity.DomainName, entity.OwnerId, entity.OrganizationId, entity.Status,
        entity.DnssecStatus, entity.DnssecDiagnostic, entity.CreatedAtUtc, entity.UpdatedAtUtc, entity.Version,
        entity.VerificationStatus, entity.VerificationMethod, entity.OwnershipVerifiedAtUtc);
    private static DomainOrganization? ToOrganization(HipDomainOrganizationEntity? entity) => entity is null ? null : new(
        entity.OrganizationId, entity.Name, entity.CreatedAtUtc, entity.UpdatedAtUtc, entity.Version);
    private static HipManagedDomainEntity ToEntity(ManagedDomain domain) => new()
    {
        DomainId = domain.DomainId, DomainName = domain.DomainName, OwnerId = domain.OwnerId,
        OrganizationId = domain.OrganizationId, Status = domain.Status, DnssecStatus = domain.DnssecStatus,
        DnssecDiagnostic = domain.DnssecDiagnostic, CreatedAtUtc = domain.CreatedAtUtc,
        UpdatedAtUtc = domain.UpdatedAtUtc, Version = domain.Version,
        VerificationStatus = domain.VerificationStatus, VerificationMethod = domain.VerificationMethod,
        OwnershipVerifiedAtUtc = domain.OwnershipVerifiedAtUtc
    };
}
