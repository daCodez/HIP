using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.Web.Security;

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

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!environment.IsDevelopment())
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!Request.Headers.TryGetValue(RoleHeaderName, out var roleValues))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var role = roleValues.ToString().Trim();
        if (!AdminRoles.All.Contains(role))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unsupported HIP admin role."));
        }

        var user = Request.Headers.TryGetValue(UserHeaderName, out var userValues)
            ? userValues.ToString().Trim()
            : "hip-dev-admin";

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
}
