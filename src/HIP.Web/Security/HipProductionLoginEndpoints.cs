using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace HIP.Web.Security;

/// <summary>Maps the external identity-provider sign-in and sign-out flow used outside Development.</summary>
public static class HipProductionLoginEndpoints
{
    internal const long MaximumAuthenticationFormBodyBytes = 4096;

    /// <summary>Adds anti-forgery-protected OIDC login and logout endpoints for a production HIP Web host.</summary>
    public static WebApplication MapHipProductionLogin(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            return app;
        }

        app.MapGet("/auth/login", SignInFromLink)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy);
        app.MapGet("/auth/register", RegisterFromLink)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy);
        app.MapPost("/auth/login", SignInAsync)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy)
            .WithMetadata(new RequestSizeLimitAttribute(MaximumAuthenticationFormBodyBytes));
        app.MapPost("/auth/logout", SignOutAsync)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy)
            .WithMetadata(new RequestSizeLimitAttribute(MaximumAuthenticationFormBodyBytes));
        app.MapPost("/auth/step-up", StepUpAsync)
            .RequireAuthorization(AdminPolicies.CanRequestPrivilegedStepUp)
            .RequireRateLimiting(RateLimitPolicies.AdminLoginPolicy)
            .WithMetadata(new RequestSizeLimitAttribute(MaximumAuthenticationFormBodyBytes));
        return app;
    }

    private static IResult SignInFromLink(string? returnUrl) =>
        Results.Challenge(
            SignInProperties(returnUrl),
            [HipAuthenticationSchemes.OpenIdConnect]);

    private static IResult RegisterFromLink(string? returnUrl)
    {
        var challenge = new OpenIdConnectChallengeProperties
        {
            RedirectUri = HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(returnUrl, "/consumer"),
            Prompt = "create"
        };
        return Results.Challenge(challenge, [HipAuthenticationSchemes.OpenIdConnect]);
    }

    private static async Task<IResult> SignInAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        CancellationToken cancellationToken)
    {
        if (!await HasValidAntiforgeryFormAsync(httpContext, antiforgery, cancellationToken))
        {
            return Results.BadRequest();
        }

        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var returnUrl = HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(form["returnUrl"].ToString());
        return Results.Challenge(
            SignInProperties(returnUrl),
            [HipAuthenticationSchemes.OpenIdConnect]);
    }

    private static AuthenticationProperties SignInProperties(string? returnUrl)
    {
        var safeReturnUrl = HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(returnUrl);
        return safeReturnUrl.StartsWith("/admin", StringComparison.OrdinalIgnoreCase)
            ? new OpenIdConnectChallengeProperties
            {
                RedirectUri = safeReturnUrl,
                Prompt = "login",
                MaxAge = TimeSpan.Zero
            }
            : new AuthenticationProperties { RedirectUri = safeReturnUrl };
    }

    private static async Task<IResult> SignOutAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        CancellationToken cancellationToken)
    {
        if (!await HasValidAntiforgeryFormAsync(httpContext, antiforgery, cancellationToken))
        {
            return Results.BadRequest();
        }

        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var requestedReturnUrl = form["returnUrl"].ToString();
        var returnUrl = string.IsNullOrWhiteSpace(requestedReturnUrl)
            ? "/login"
            : HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(requestedReturnUrl);
        return Results.SignOut(
            new AuthenticationProperties { RedirectUri = returnUrl },
            [HipAuthenticationSchemes.SessionCookie, HipAuthenticationSchemes.OpenIdConnect]);
    }

    private static async Task<IResult> StepUpAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        if (!await HasValidAntiforgeryFormAsync(httpContext, antiforgery, cancellationToken))
        {
            return Results.BadRequest();
        }

        var currentSession = await httpContext.AuthenticateAsync(HipAuthenticationSchemes.SessionCookie);
        var actorClaims = currentSession.Principal?.FindAll(HipAuthenticationClaimTypes.ActorId).ToArray() ?? [];
        if (!currentSession.Succeeded ||
            currentSession.Properties is null ||
            actorClaims.Length != 1 ||
            string.IsNullOrWhiteSpace(actorClaims[0].Value) ||
            !HipSessionAuthenticationProperties.TryGetAbsoluteExpiry(
                currentSession.Properties,
                out var originalAbsoluteExpiry) ||
            originalAbsoluteExpiry <= timeProvider.GetUtcNow())
        {
            return Results.Forbid();
        }

        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var returnUrl = HipDevelopmentLoginEndpoints.SafeLocalReturnUrl(form["returnUrl"].ToString());
        var challenge = new OpenIdConnectChallengeProperties
        {
            RedirectUri = returnUrl,
            Prompt = "login",
            MaxAge = TimeSpan.Zero
        };
        HipStepUpAuthenticationProperties.SetStepUpMarker(challenge);
        HipStepUpAuthenticationProperties.SetExpectedActorId(challenge, actorClaims[0].Value);
        HipStepUpAuthenticationProperties.SetOriginalAbsoluteExpiry(challenge, originalAbsoluteExpiry);
        return Results.Challenge(challenge, [HipAuthenticationSchemes.OpenIdConnect]);
    }

    private static async Task<bool> HasValidAntiforgeryFormAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        CancellationToken cancellationToken)
    {
        if (!httpContext.Request.HasFormContentType)
        {
            return false;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }
}
