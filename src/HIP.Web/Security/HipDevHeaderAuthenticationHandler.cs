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
    public const string ConsumerHeaderName = "X-HIP-Consumer-Id";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!environment.IsDevelopment())
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!Request.Headers.TryGetValue(RoleHeaderName, out var roleValues))
        {
            return AuthenticateConsumer();
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
