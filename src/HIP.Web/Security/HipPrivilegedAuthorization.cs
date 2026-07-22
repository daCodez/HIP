using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Requires Owner and Administrator principals to carry HIP-reduced MFA evidence outside Development.
/// </summary>
public sealed class PrivilegedMfaRequirement : IAuthorizationRequirement
{
}

/// <summary>
/// Requires privileged principals to carry recent HIP-reduced MFA authentication-time evidence.
/// </summary>
public sealed class RecentPrivilegedMfaRequirement : IAuthorizationRequirement
{
}

/// <summary>
/// Enforces MFA for privileged HIP roles without changing the isolated Development authentication workflow.
/// </summary>
public sealed class PrivilegedMfaRequirementHandler(IHostEnvironment environment)
    : AuthorizationHandler<PrivilegedMfaRequirement>
{
    /// <inheritdoc />
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PrivilegedMfaRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        if (environment.IsDevelopment() ||
            !HipPrivilegedAuthenticationEvidence.IsPrivileged(context.User) ||
            HipPrivilegedAuthenticationEvidence.HasCanonicalMfa(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// Enforces the configured privileged-authentication age and clock-skew bounds outside Development.
/// </summary>
public sealed class RecentPrivilegedMfaRequirementHandler(
    IHostEnvironment environment,
    IOptions<HipProductionAuthenticationOptions> configuredOptions,
    TimeProvider timeProvider)
    : AuthorizationHandler<RecentPrivilegedMfaRequirement>
{
    /// <inheritdoc />
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RecentPrivilegedMfaRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);

        if (environment.IsDevelopment() || !HipPrivilegedAuthenticationEvidence.IsPrivileged(context.User))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var recentAuthenticationLifetime = configuredOptions.Value.RecentAuthenticationLifetime;
        if (recentAuthenticationLifetime < HipProductionAuthenticationOptions.MinimumRecentAuthenticationLifetime ||
            recentAuthenticationLifetime > HipProductionAuthenticationOptions.MaximumRecentAuthenticationLifetime ||
            !HipPrivilegedAuthenticationEvidence.HasCanonicalMfa(context.User) ||
            !HipPrivilegedAuthenticationEvidence.TryGetAuthenticationTime(context.User, out var authenticationTime))
        {
            return Task.CompletedTask;
        }

        var now = timeProvider.GetUtcNow();
        if (authenticationTime <= now + HipExternalAuthenticationAssuranceEvaluator.MaximumAuthenticationClockSkew &&
            authenticationTime >= now - recentAuthenticationLifetime)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

internal static class HipPrivilegedAuthenticationEvidence
{
    public static bool IsPrivileged(ClaimsPrincipal principal) =>
        principal.IsInRole(AdminRoles.Owner) || principal.IsInRole(AdminRoles.Admin);

    public static bool HasCanonicalMfa(ClaimsPrincipal principal)
    {
        var claims = principal.FindAll(HipAuthenticationClaimTypes.MultiFactorAuthenticated).Take(2).ToArray();
        return claims.Length == 1 &&
               string.Equals(claims[0].Value, "true", StringComparison.Ordinal) &&
               string.Equals(claims[0].ValueType, ClaimValueTypes.Boolean, StringComparison.Ordinal);
    }

    public static bool TryGetAuthenticationTime(
        ClaimsPrincipal principal,
        out DateTimeOffset authenticationTime)
    {
        authenticationTime = default;
        var claims = principal.FindAll(HipAuthenticationClaimTypes.AuthenticationTime).Take(2).ToArray();
        if (claims.Length != 1 ||
            !string.Equals(claims[0].ValueType, ClaimValueTypes.Integer64, StringComparison.Ordinal) ||
            !long.TryParse(
                claims[0].Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var unixTimeSeconds) ||
            !string.Equals(
                claims[0].Value,
                unixTimeSeconds.ToString(CultureInfo.InvariantCulture),
                StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            authenticationTime = DateTimeOffset.FromUnixTimeSeconds(unixTimeSeconds);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }
}
