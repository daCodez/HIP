using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace HIP.Web.Security;

/// <summary>
/// Resolves HIP-owned identity claims without accepting missing, blank, unauthenticated, or ambiguous identities.
/// </summary>
public static class HipAuthenticatedIdentity
{
    /// <summary>
    /// Resolves exactly one nonblank claim from an authenticated principal.
    /// </summary>
    public static bool TryResolveUniqueClaim(
        ClaimsPrincipal principal,
        string claimType,
        out string value)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(claimType);

        value = string.Empty;
        var claims = principal.Identities
            .Where(identity => identity.IsAuthenticated)
            .SelectMany(identity => identity.FindAll(claimType))
            .Take(2)
            .ToArray();
        if (claims.Length != 1 || string.IsNullOrWhiteSpace(claims[0].Value))
        {
            return false;
        }

        value = claims[0].Value.Trim();
        return true;
    }

    /// <summary>
    /// Returns the unique HIP identity claim after authorization has established the same invariant.
    /// </summary>
    /// <exception cref="InvalidOperationException">The principal does not contain exactly one usable claim.</exception>
    public static string ResolveRequiredUniqueClaim(ClaimsPrincipal principal, string claimType) =>
        TryResolveUniqueClaim(principal, claimType, out var value)
            ? value
            : throw new InvalidOperationException("The authenticated HIP identity is incomplete or ambiguous.");
}

/// <summary>
/// Requires one authenticated, nonblank, unambiguous HIP-owned identity claim.
/// </summary>
public sealed class UniqueHipIdentityClaimRequirement : IAuthorizationRequirement
{
    public UniqueHipIdentityClaimRequirement(string claimType)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(claimType);
        ClaimType = claimType;
    }

    /// <summary>Gets the HIP-owned claim type required by the protected surface.</summary>
    public string ClaimType { get; }
}

/// <summary>
/// Enforces <see cref="UniqueHipIdentityClaimRequirement" /> before protected handlers can run.
/// </summary>
public sealed class UniqueHipIdentityClaimRequirementHandler
    : AuthorizationHandler<UniqueHipIdentityClaimRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        UniqueHipIdentityClaimRequirement requirement)
    {
        if (HipAuthenticatedIdentity.TryResolveUniqueClaim(
                context.User,
                requirement.ClaimType,
                out _))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
