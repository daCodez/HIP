using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

/// <summary>
/// Development-only authentication handler for local HIP admin and consumer testing.
/// </summary>
/// <remarks>
/// Production deployments must replace this handler with real authentication. In development it accepts
/// explicit test headers for API tests and a local dev cookie so browser navigation can exercise protected UI.
/// These development credentials are accepted only for localhost requests so accidental Development deployments
/// do not expose an admin bypass on a network host.
/// </remarks>
public sealed class HipDevHeaderAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IWebHostEnvironment environment)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "HipDevHeader";
    public const string RoleHeaderName = "X-HIP-Admin-Role";
    public const string UserHeaderName = "X-HIP-Admin-User";
    public const string ConsumerHeaderName = "X-HIP-Consumer-Id";
    public const string DevAdminRoleCookieName = "HIP_DEV_ADMIN_ROLE";
    public const string DevAdminUserCookieName = "HIP_DEV_ADMIN_USER";

    /// <summary>
    /// Authenticates local development requests from explicit headers, then from dev-only browser cookies.
    /// </summary>
    /// <returns>Authentication result for the current request.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!environment.IsDevelopment())
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(Request, environment))
        {
            Logger.LogWarning("Blocked non-local HIP development auth attempt for host {Host}.", Request.Host.Value);
            return Task.FromResult(AuthenticateResult.Fail("HIP development authentication is local-only."));
        }

        if (!Request.Headers.TryGetValue(RoleHeaderName, out var roleValues))
        {
            return Request.Cookies.TryGetValue(DevAdminRoleCookieName, out var cookieRole)
                ? AuthenticateAdmin(cookieRole, Request.Cookies.TryGetValue(DevAdminUserCookieName, out var cookieUser) ? cookieUser : "hip-dev-admin")
                : AuthenticateConsumer();
        }

        return AuthenticateAdmin(
            roleValues.ToString(),
            Request.Headers.TryGetValue(UserHeaderName, out var userValues) ? userValues.ToString() : "hip-dev-admin");
    }

    /// <summary>
    /// Creates an admin principal after validating the requested development role.
    /// </summary>
    /// <param name="roleValue">Role from a dev header or dev cookie.</param>
    /// <param name="userValue">User name from a dev header or dev cookie.</param>
    /// <returns>Authentication result containing admin claims or a failure for unsupported roles.</returns>
    private static Task<AuthenticateResult> AuthenticateAdmin(string roleValue, string userValue)
    {
        var role = roleValue.Trim();
        if (!AdminRoles.All.Contains(role))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unsupported HIP admin role."));
        }

        var user = userValue.Trim();
        if (string.IsNullOrWhiteSpace(user))
        {
            user = "hip-dev-admin";
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user),
            new Claim(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    /// <summary>
    /// Authenticates local consumer test requests without exposing private consumer data.
    /// </summary>
    /// <returns>Consumer authentication result when a dev consumer header exists.</returns>
    private Task<AuthenticateResult> AuthenticateConsumer()
    {
        if (!Request.Headers.TryGetValue(ConsumerHeaderName, out var consumerValues))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var consumerId = consumerValues.ToString().Trim();
        if (string.IsNullOrWhiteSpace(consumerId))
        {
            return Task.FromResult(AuthenticateResult.Fail("Consumer ID is required."));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, consumerId),
            new Claim("hip_consumer_id", consumerId)
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
