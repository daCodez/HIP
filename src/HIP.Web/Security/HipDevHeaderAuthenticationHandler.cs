using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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

        if (Request.Headers.TryGetValue(RoleHeaderName, out var roleValues))
        {
            return AuthenticateAdmin(
                roleValues.ToString(),
                Request.Headers.TryGetValue(UserHeaderName, out var userValues)
                    ? userValues.ToString()
                    : "hip-dev-admin");
        }

        if (Request.Headers.TryGetValue(ConsumerHeaderName, out var consumerValues))
        {
            return AuthenticateConsumer(consumerValues.ToString());
        }

        return Request.Cookies.TryGetValue(DevAdminRoleCookieName, out var cookieRole)
            ? AuthenticateAdmin(
                cookieRole,
                HipDevelopmentActorId.FromSubject(
                    Request.Cookies.TryGetValue(DevAdminUserCookieName, out var cookieUser)
                        ? cookieUser
                        : "hip-dev-admin"),
                includeConsumerIdentity: true)
            : Task.FromResult(AuthenticateResult.NoResult());
    }

    /// <summary>
    /// Redirects local development browser requests for protected portal pages to the credential form.
    /// </summary>
    /// <param name="properties">Authentication challenge properties supplied by ASP.NET Core authorization.</param>
    /// <returns>A completed task after the response challenge is written.</returns>
    /// <remarks>
    /// This deliberately applies only to local Development portal navigation. API requests still receive a 401
    /// so automated clients do not silently follow a browser login redirect, and non-local Development hosts
    /// never receive the dev login path.
    /// </remarks>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(Request, environment) &&
            Request.Path.StartsWithSegments("/admin"))
        {
            var returnUrl = Uri.EscapeDataString($"{Request.PathBase}{Request.Path}{Request.QueryString}");
            Response.Redirect($"/login?returnUrl={returnUrl}");
            return Task.CompletedTask;
        }

        if (LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(Request, environment) &&
            Request.Path.StartsWithSegments("/consumer"))
        {
            var returnUrl = Uri.EscapeDataString($"{Request.PathBase}{Request.Path}{Request.QueryString}");
            Response.Redirect($"/login?returnUrl={returnUrl}");
            return Task.CompletedTask;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates an admin principal after validating the requested development role.
    /// </summary>
    /// <param name="roleValue">Role from a dev header or dev cookie.</param>
    /// <param name="userValue">User name from a dev header or dev cookie.</param>
    /// <returns>Authentication result containing admin claims or a failure for unsupported roles.</returns>
    private static Task<AuthenticateResult> AuthenticateAdmin(
        string roleValue,
        string userValue,
        bool includeConsumerIdentity = false)
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

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user),
            new(ClaimTypes.Role, role),
            new(HipAuthenticationClaimTypes.ActorId, user)
        };
        if (includeConsumerIdentity)
        {
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.ConsumerId,
                DevelopmentConsumerId(user)));
            claims.Add(new Claim(
                HipAuthenticationClaimTypes.AccountContactVerified,
                "true",
                ClaimValueTypes.Boolean));
        }

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    /// <summary>
    /// Authenticates local consumer test requests without exposing private consumer data.
    /// </summary>
    /// <returns>Consumer authentication result for an explicit test header.</returns>
    private static Task<AuthenticateResult> AuthenticateConsumer(string consumerValue)
    {
        var consumerId = consumerValue.Trim();
        if (string.IsNullOrWhiteSpace(consumerId))
        {
            return Task.FromResult(AuthenticateResult.Fail("Consumer ID is required."));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, consumerId),
            new Claim(HipAuthenticationClaimTypes.ConsumerId, consumerId),
            new Claim(
                HipAuthenticationClaimTypes.AccountContactVerified,
                "true",
                ClaimValueTypes.Boolean)
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private static string DevelopmentConsumerId(string accountSubject)
    {
        var subjectBytes = Encoding.UTF8.GetBytes($"hip-development-consumer:{accountSubject.Trim()}");
        return $"local-account-{Convert.ToHexString(SHA256.HashData(subjectBytes)).ToLowerInvariant()}";
    }

}

/// <summary>
/// Converts development authentication subjects into stable actor identifiers without placing email addresses in claims.
/// </summary>
internal static class HipDevelopmentActorId
{
    /// <summary>Returns an existing privacy-safe identifier or a domain-separated SHA-256 identifier.</summary>
    internal static string FromSubject(string subject)
    {
        var trimmed = subject.Trim();
        if (trimmed.Length is >= 2 and <= 160 &&
            char.IsAsciiLetterOrDigit(trimmed[0]) &&
            trimmed.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is ':' or '.' or '_' or '-'))
        {
            return trimmed;
        }

        var normalizedSubject = trimmed.ToLowerInvariant();
        var material = Encoding.UTF8.GetBytes($"hip-development-admin:v1\0{normalizedSubject}");
        return $"hip-user:v1:{Convert.ToHexString(SHA256.HashData(material)).ToLowerInvariant()}";
    }
}
