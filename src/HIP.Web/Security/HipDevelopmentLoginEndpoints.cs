using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

namespace HIP.Web.Security;

/// <summary>
/// Maps the password-backed local administrator session used before HIP has a hosted identity provider.
/// </summary>
public static class HipDevelopmentLoginEndpoints
{
    /// <summary>
    /// Adds local-only sign-in and sign-out endpoints with anti-forgery, attempt limiting, and safe redirects.
    /// </summary>
    public static WebApplication MapHipDevelopmentLogin(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            return app;
        }

        app.MapPost("/auth/login", SignInAsync)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy);

        app.MapPost("/auth/logout", SignOutAsync).AllowAnonymous();
        return app;
    }

    private static async Task<IResult> SignInAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IHipAdminAuthenticationProvider authenticationProvider,
        IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        if (!LocalDevelopmentRequestGuard.IsLocalDevelopmentRequest(httpContext.Request, environment))
        {
            return Results.NotFound();
        }

        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        if (!httpContext.Request.HasFormContentType)
        {
            return Results.BadRequest();
        }

        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var safeReturnUrl = SafeLocalReturnUrl(form["returnUrl"].ToString());
        var authentication = await authenticationProvider.AuthenticateAsync(
            new HipAdminAuthenticationRequest(email, password),
            cancellationToken);

        if (!authentication.IsAuthenticated || authentication.Identity is null)
        {
            var returnQuery = Uri.EscapeDataString(safeReturnUrl);
            return Results.Redirect($"/login?error=invalid&returnUrl={returnQuery}");
        }

        var remember = string.Equals(form["remember"], "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(form["remember"], "on", StringComparison.OrdinalIgnoreCase);
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Strict,
            Secure = httpContext.Request.IsHttps,
            Path = "/",
            Expires = remember ? DateTimeOffset.UtcNow.AddDays(30) : null
        };

        httpContext.Response.Cookies.Append(
            HipDevHeaderAuthenticationHandler.DevAdminRoleCookieName,
            authentication.Identity.Role,
            cookieOptions);
        httpContext.Response.Cookies.Append(
            HipDevHeaderAuthenticationHandler.DevAdminUserCookieName,
            authentication.Identity.Subject,
            cookieOptions);
        return Results.Redirect(safeReturnUrl);
    }

    private static async Task<IResult> SignOutAsync(HttpContext httpContext, IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        httpContext.Response.Cookies.Delete(HipDevHeaderAuthenticationHandler.DevAdminRoleCookieName, new CookieOptions { Path = "/" });
        httpContext.Response.Cookies.Delete(HipDevHeaderAuthenticationHandler.DevAdminUserCookieName, new CookieOptions { Path = "/" });
        return Results.Redirect("/login");
    }

    /// <summary>
    /// Returns a local path or the administrator home page when the requested path could leave HIP.
    /// </summary>
    internal static string SafeLocalReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return "/admin";
        }

        var trimmed = returnUrl.Trim();
        return trimmed.StartsWith("/", StringComparison.Ordinal) &&
               !trimmed.StartsWith("//", StringComparison.Ordinal) &&
               !trimmed.StartsWith("/\\", StringComparison.Ordinal) &&
               !Uri.TryCreate(trimmed, UriKind.Absolute, out _)
            ? trimmed
            : "/admin";
    }
}
