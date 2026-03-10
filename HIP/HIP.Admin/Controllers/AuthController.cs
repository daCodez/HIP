using System.Security.Claims;
using HIP.Admin.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace HIP.Admin.Controllers;

[AllowAnonymous]
[Route("auth")]
[Route("admin/auth")]
public sealed class AuthController(IOptions<AdminAuthOptions> authOptionsAccessor, ILogger<AuthController> logger) : Controller
{
    private readonly AdminAuthOptions _authOptions = authOptionsAccessor.Value;
    private readonly ILogger<AuthController> _logger = logger;

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl = "/")
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return LocalRedirect(SanitizeReturnUrl(returnUrl));
        }

        if (!_authOptions.EnableOidc)
        {
            return LocalRedirect($"/login?returnUrl={Uri.EscapeDataString(SanitizeReturnUrl(returnUrl))}");
        }

        var redirectUri = Url.Action(nameof(LoginCallback), new { returnUrl = SanitizeReturnUrl(returnUrl) }) ?? "/";
        _logger.LogInformation("auth.oidc.challenge.started returnUrl={ReturnUrl}", SanitizeReturnUrl(returnUrl));
        return Challenge(new AuthenticationProperties { RedirectUri = redirectUri }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpPost("local-login")]
    public async Task<IActionResult> LocalLogin([FromForm] string? username, [FromForm] string? password, [FromForm] string? returnUrl = "/")
    {
        var target = NormalizeAdminReturnUrl(SanitizeReturnUrl(returnUrl));

        if (!_authOptions.EnableLocalAuth)
        {
            _logger.LogWarning("auth.local.login.denied reason=local_auth_disabled user={Username}", username ?? "<null>");
            return LocalRedirect($"/login?error={Uri.EscapeDataString("local_auth_disabled")}&returnUrl={Uri.EscapeDataString(target)}");
        }

        if (string.IsNullOrWhiteSpace(_authOptions.LocalAdmin.Password))
        {
            _logger.LogWarning("auth.local.login.denied reason=local_admin_not_configured user={Username}", username ?? "<null>");
            return LocalRedirect($"/login?error={Uri.EscapeDataString("local_admin_not_configured")}&returnUrl={Uri.EscapeDataString(target)}");
        }

        if (!string.Equals(username?.Trim(), _authOptions.LocalAdmin.Username, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(password, _authOptions.LocalAdmin.Password, StringComparison.Ordinal))
        {
            _logger.LogWarning("auth.local.login.failed user={Username}", username ?? "<null>");
            return LocalRedirect($"/login?error={Uri.EscapeDataString("invalid_credentials")}&returnUrl={Uri.EscapeDataString(target)}");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, _authOptions.LocalAdmin.Username),
            new("app:role", "Admin")
        };

        foreach (var role in _authOptions.LocalAdmin.Roles.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            claims.Add(new Claim("app:role", role));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(12)
            });

        _logger.LogInformation("auth.local.login.succeeded user={Username} roles={Roles}", _authOptions.LocalAdmin.Username, string.Join(',', _authOptions.LocalAdmin.Roles));
        return LocalRedirect(target);
    }

    [HttpGet("callback")]
    public IActionResult LoginCallback([FromQuery] string? returnUrl = "/")
    {
        _logger.LogInformation("auth.oidc.login.succeeded returnUrl={ReturnUrl}", SanitizeReturnUrl(returnUrl));
        return LocalRedirect(SanitizeReturnUrl(returnUrl));
    }

    [HttpGet("logout")]
    public IActionResult Logout([FromQuery] string? returnUrl = "/")
    {
        var redirectUri = Url.Action(nameof(LoggedOut), new { returnUrl = SanitizeReturnUrl(returnUrl) }) ?? "/";
        _logger.LogInformation("auth.logout.started oidcEnabled={OidcEnabled} returnUrl={ReturnUrl}", _authOptions.EnableOidc, SanitizeReturnUrl(returnUrl));
        if (_authOptions.EnableOidc)
        {
            return SignOut(new AuthenticationProperties { RedirectUri = redirectUri }, CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
        }

        return SignOut(new AuthenticationProperties { RedirectUri = redirectUri }, CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [HttpGet("logged-out")]
    public IActionResult LoggedOut([FromQuery] string? returnUrl = "/")
        => LocalRedirect(SanitizeReturnUrl(returnUrl));

    private string SanitizeReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return returnUrl;
        }

        return "/admin";
    }

    private static string NormalizeAdminReturnUrl(string returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl) ||
            returnUrl == "/" ||
            returnUrl.Equals("/login", StringComparison.OrdinalIgnoreCase) ||
            returnUrl.Equals("/admin/login", StringComparison.OrdinalIgnoreCase))
        {
            return "/admin";
        }

        return returnUrl;
    }
}
