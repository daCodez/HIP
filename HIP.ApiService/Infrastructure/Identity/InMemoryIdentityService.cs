using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Application.Contracts;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HIP.ApiService.Infrastructure.Identity;

/// <summary>
/// Executes the operation for this public API member.
/// </summary>
/// <param name="db">The db value used by this operation.</param>
/// <param name="logger">The logger value used by this operation.</param>
/// <returns>The operation result.</returns>
public sealed class InMemoryIdentityService(HipDbContext db, ILogger<InMemoryIdentityService> logger) : IIdentityService
{
    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <param name="id">The id value used by this operation.</param>
    /// <param name="cancellationToken">The cancellationToken value used by this operation.</param>
    /// <returns>The operation result.</returns>
    public async Task<IdentityDto?> GetByIdAsync(string id, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id); // validation
        logger.LogDebug("Identity lookup requested for {IdentityId}", id); // logging/security awareness: no secrets

        var entity = await db.Identities.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return entity is null
            ? null
            : new IdentityDto(entity.Id, entity.PublicKeyRef); // performance awareness: no over-fetch
    }
}
