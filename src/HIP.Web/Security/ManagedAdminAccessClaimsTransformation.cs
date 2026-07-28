using System.Security.Claims;
using HIP.Application.Administration;
using Microsoft.AspNetCore.Authentication;

namespace HIP.Web.Security;

/// <summary>
/// Replaces externally asserted admin roles with HIP-managed assignments after the first directory is created.
/// External identity providers remain responsible for authentication, while HIP remains authoritative for application access.
/// </summary>
public sealed class ManagedAdminAccessClaimsTransformation(
    IAdminAccessRepository repository,
    ILogger<ManagedAdminAccessClaimsTransformation> logger) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        AdminAccessDirectory? directory;
        try
        {
            directory = await repository.GetAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            logger.LogWarning("HIP administrator access is unavailable; administrator role claims were removed for this request.");
            return WithoutAdminRoles(principal);
        }

        if (directory is null)
        {
            return principal;
        }

        var transformed = Clone(principal);
        var identities = transformed.Identities.Cast<ClaimsIdentity>().ToArray();
        if (!HipAuthenticatedIdentity.TryResolveUniqueClaim(
                transformed,
                HipAuthenticationClaimTypes.ActorId,
                out var actorId))
        {
            RemoveAdminRoles(identities);
            return transformed;
        }

        var assignment = directory.Assignments.SingleOrDefault(
            item => string.Equals(item.ActorId, actorId, StringComparison.Ordinal));
        RemoveAdminRoles(identities);
        if (assignment is { Status: AdminAccessStatus.Active })
        {
            var identity = identities.SingleOrDefault(item =>
                item.HasClaim(claim =>
                    claim.Type == HipAuthenticationClaimTypes.ActorId &&
                    string.Equals(claim.Value, actorId, StringComparison.Ordinal)));
            identity?.AddClaim(new Claim(identity.RoleClaimType, assignment.Role));
        }

        return transformed;
    }

    private static ClaimsPrincipal WithoutAdminRoles(ClaimsPrincipal principal)
    {
        var transformed = Clone(principal);
        RemoveAdminRoles(transformed.Identities.Cast<ClaimsIdentity>());
        return transformed;
    }

    private static ClaimsPrincipal Clone(ClaimsPrincipal principal) =>
        new(principal.Identities.Select(identity => new ClaimsIdentity(identity)));

    private static void RemoveAdminRoles(IEnumerable<ClaimsIdentity> identities)
    {
        foreach (var identity in identities)
        {
            foreach (var claim in identity.FindAll(identity.RoleClaimType).ToArray())
            {
                if (AdminAccessRoleNames.All.Contains(claim.Value))
                {
                    identity.RemoveClaim(claim);
                }
            }
        }
    }
}