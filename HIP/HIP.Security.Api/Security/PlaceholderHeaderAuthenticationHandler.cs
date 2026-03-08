using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace HIP.Security.Api.Security;

public sealed class PlaceholderHeaderAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "HipSecurityHeader";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var principalId = Request.Headers["X-HIP-Principal"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(principalId))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing X-HIP-Principal header."));
        }

        var role = Request.Headers["X-HIP-Role"].FirstOrDefault() ?? "SecurityOperator";
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, principalId),
            new Claim(ClaimTypes.Name, principalId),
            new Claim(ClaimTypes.Role, role)
        };

        var identity = new ClaimsIdentity(claims, SchemeName);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
