using System.IdentityModel.Tokens.Jwt;
using System.Globalization;
using System.Security.Claims;
using HIP.Tests.Support;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies HIP authentication events reduce external claims and enforce idle and absolute session bounds.
/// </summary>
public sealed class HipAuthenticationEventTests
{
    [Test]
    public async Task Token_validation_keeps_a_bounded_display_label_but_removes_external_personal_claims()
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var context = TokenContext(
            options,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-subject-1"),
                new Claim("roles", "hip-owner"),
                new Claim("amr", "pwd"),
                new Claim("amr", "mfa"),
                new Claim("auth_time", time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
                new Claim(ClaimTypes.Email, "private@example.test"),
                new Claim(ClaimTypes.Name, "Private Name")));

        await events.TokenValidated(context);

        var claims = context.Principal!.Claims.ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(context.Result, Is.Null);
            Assert.That(claims.Select(claim => claim.Type), Is.EquivalentTo(new[]
            {
                ClaimTypes.NameIdentifier,
                HipAuthenticationClaimTypes.ActorId,
                HipAuthenticationClaimTypes.ConsumerId,
                HipAuthenticationClaimTypes.DisplayName,
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                HipAuthenticationClaimTypes.AuthenticationTime,
                ClaimTypes.Role
            }));
            Assert.That(claims.Single(claim => claim.Type == ClaimTypes.Role).Value, Is.EqualTo(AdminRoles.Owner));
            Assert.That(claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.DisplayName).Value, Is.EqualTo("Private Name"));
            Assert.That(claims.Any(claim => claim.Type == ClaimTypes.Name), Is.False);
            Assert.That(
                claims.Single(claim => claim.Type == HipAuthenticationClaimTypes.MultiFactorAuthenticated).Value,
                Is.EqualTo("true"));
            Assert.That(claims.Any(claim => claim.Value.Contains("private@example.test", StringComparison.Ordinal)), Is.False);
            Assert.That(context.Properties!.IssuedUtc, Is.EqualTo(time.GetUtcNow()));
            Assert.That(context.Properties.ExpiresUtc, Is.EqualTo(time.GetUtcNow().AddMinutes(30)));
        });
    }

    [Test]
    public async Task Missing_external_identity_claim_rejects_the_ticket_with_a_generic_failure()
    {
        const string sensitiveValue = "sensitive-external-claim";
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var context = TokenContext(
            options,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(ClaimTypes.Email, sensitiveValue)));

        await events.TokenValidated(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Failure, Is.Not.Null);
            Assert.That(context.Result!.Failure!.Message, Does.Not.Contain(sensitiveValue));
            Assert.That(context.Result.Failure.Message, Does.Not.Contain("sub"));
        });
    }

    [TestCase(AdminRoles.Owner, "hip-owner")]
    [TestCase(AdminRoles.Admin, "hip-admin")]
    public async Task Privileged_login_without_accepted_mfa_fails_closed(
        string expectedRole,
        string externalRole)
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var context = TokenContext(
            options,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-privileged-subject"),
                new Claim("roles", externalRole),
                new Claim("amr", "pwd"),
                new Claim("auth_time", time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))));

        await events.TokenValidated(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Failure, Is.Not.Null, expectedRole);
            Assert.That(context.Principal, Is.Null);
            Assert.That(context.Result!.Failure!.Message, Does.Not.Contain(externalRole));
        });
    }

    [Test]
    public async Task Forged_hip_assurance_claims_cannot_satisfy_a_privileged_login()
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var context = TokenContext(
            options,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-privileged-subject"),
                new Claim("roles", "hip-owner"),
                new Claim("amr", "pwd"),
                new Claim(HipAuthenticationClaimTypes.MultiFactorAuthenticated, "true"),
                new Claim(
                    HipAuthenticationClaimTypes.AuthenticationTime,
                    time.GetUtcNow().ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))));

        await events.TokenValidated(context);

        Assert.That(context.Result?.Failure, Is.Not.Null);
    }

    [TestCase(false, 0)]
    [TestCase(true, 481)]
    public async Task Privileged_login_requires_exactly_one_auth_time_within_the_absolute_session_bound(
        bool includeAuthenticationTime,
        int authenticationAgeMinutes)
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var time = new AdjustableTimeProvider(now);
        var events = CreateOidcEvents(time, out var options);
        var claims = new List<Claim>
        {
            new(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
            new(HipAuthenticationClaimTypes.Subject, "opaque-privileged-subject"),
            new("roles", "hip-owner"),
            new("amr", "mfa")
        };
        if (includeAuthenticationTime)
        {
            claims.Add(new Claim(
                "auth_time",
                now.AddMinutes(-authenticationAgeMinutes)
                    .ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture)));
        }

        var context = TokenContext(options, ExternalPrincipal(claims.ToArray()));

        await events.TokenValidated(context);

        Assert.That(context.Result?.Failure, Is.Not.Null);
    }

    [Test]
    public async Task Redirect_to_identity_provider_requests_only_configured_acr_values()
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var authOptions = ValidOptions();
        authOptions.TrustedMfaAcrValues = ["urn:hip:test:mfa", "urn:hip:test:phishing-resistant"];
        var events = CreateOidcEvents(time, authOptions, out var options);
        var context = new Microsoft.AspNetCore.Authentication.OpenIdConnect.RedirectContext(
            new DefaultHttpContext(),
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            new AuthenticationProperties())
        {
            ProtocolMessage = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage()
        };

        await events.RedirectToIdentityProvider(context);

        Assert.That(
            context.ProtocolMessage.AcrValues,
            Is.EqualTo("urn:hip:test:mfa urn:hip:test:phishing-resistant"));
    }

    [Test]
    public void Step_up_properties_round_trip_and_clear_all_one_time_state()
    {
        var properties = new AuthenticationProperties();
        var absoluteExpiry = new DateTimeOffset(2026, 7, 19, 20, 0, 0, TimeSpan.Zero);
        HipStepUpAuthenticationProperties.SetStepUpMarker(properties);
        HipStepUpAuthenticationProperties.SetExpectedActorId(properties, "hip-user:v1:test-actor");
        HipStepUpAuthenticationProperties.SetOriginalAbsoluteExpiry(properties, absoluteExpiry);

        Assert.Multiple(() =>
        {
            Assert.That(HipStepUpAuthenticationProperties.IsStepUp(properties), Is.True);
            Assert.That(
                HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out var actorId) &&
                actorId == "hip-user:v1:test-actor",
                Is.True);
            Assert.That(
                HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(properties, out var expiry) &&
                expiry == absoluteExpiry,
                Is.True);
        });

        HipStepUpAuthenticationProperties.Clear(properties);

        Assert.Multiple(() =>
        {
            Assert.That(HipStepUpAuthenticationProperties.IsStepUp(properties), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out _), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(properties, out _), Is.False);
        });
    }

    [Test]
    public async Task Valid_step_up_is_actor_bound_recent_and_cannot_extend_the_original_absolute_expiry()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var time = new AdjustableTimeProvider(now);
        var authOptions = ValidOptions();
        var configured = Options.Create(authOptions);
        var events = CreateOidcEvents(time, authOptions, out var options);
        var externalPrincipal = AssuredPrivilegedPrincipal(time.GetUtcNow());
        var actorId = new HipExternalClaimsMapper(configured)
            .Map(externalPrincipal)
            .Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId)
            .Value;
        var originalAbsoluteExpiry = now.AddMinutes(5);
        var properties = StepUpProperties(actorId, originalAbsoluteExpiry);
        var context = TokenContext(options, externalPrincipal, properties);

        await events.TokenValidated(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result, Is.Null);
            Assert.That(context.Properties!.ExpiresUtc, Is.EqualTo(originalAbsoluteExpiry));
            Assert.That(HipStepUpAuthenticationProperties.IsStepUp(context.Properties), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetExpectedActorId(context.Properties, out _), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(context.Properties, out _), Is.False);
        });
    }

    [Test]
    public async Task Step_up_actor_mismatch_fails_generically_and_preserves_protected_failure_routing_state()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var time = new AdjustableTimeProvider(now);
        var events = CreateOidcEvents(time, out var options);
        var properties = StepUpProperties("hip-user:v1:different-actor", now.AddHours(1));
        var context = TokenContext(options, AssuredPrivilegedPrincipal(now), properties);

        await events.TokenValidated(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Failure, Is.Not.Null);
            Assert.That(context.Principal, Is.Null);
            Assert.That(context.Result!.Failure!.Message, Does.Not.Contain("different-actor"));
            Assert.That(HipStepUpAuthenticationProperties.IsStepUp(properties), Is.True);
            Assert.That(HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out _), Is.True);
            Assert.That(HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(properties, out _), Is.True);
        });
    }

    [Test]
    public async Task Step_up_with_stale_authentication_time_fails_closed()
    {
        var now = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var time = new AdjustableTimeProvider(now);
        var authOptions = ValidOptions();
        var configured = Options.Create(authOptions);
        var stalePrincipal = AssuredPrivilegedPrincipal(now.AddMinutes(-11));
        var actorId = new HipExternalClaimsMapper(configured)
            .Map(stalePrincipal)
            .Single(claim => claim.Type == HipAuthenticationClaimTypes.ActorId)
            .Value;
        var events = CreateOidcEvents(time, authOptions, out var options);
        var context = TokenContext(options, stalePrincipal, StepUpProperties(actorId, now.AddHours(1)));

        await events.TokenValidated(context);

        Assert.That(context.Result?.Failure, Is.Not.Null);
    }

    [Test]
    public async Task Sliding_idle_renewal_is_capped_by_the_original_absolute_expiry()
    {
        var startedAt = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var time = new AdjustableTimeProvider(startedAt);
        var authOptions = ValidOptions();
        authOptions.AbsoluteSessionLifetime = TimeSpan.FromMinutes(40);
        var oidcEvents = CreateOidcEvents(time, authOptions, out var oidcOptions);
        var tokenContext = TokenContext(
            oidcOptions,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-subject-1")));
        await oidcEvents.TokenValidated(tokenContext);
        time.Advance(TimeSpan.FromMinutes(20));
        var cookieEvents = new HipSessionCookieEvents(Options.Create(authOptions), time);
        var cookieContext = CookieContext(tokenContext.Principal!, tokenContext.Properties!);

        await cookieEvents.ValidatePrincipal(cookieContext);

        Assert.Multiple(() =>
        {
            Assert.That(cookieContext.ShouldRenew, Is.True);
            Assert.That(cookieContext.Properties.IssuedUtc, Is.EqualTo(time.GetUtcNow()));
            Assert.That(cookieContext.Properties.ExpiresUtc, Is.EqualTo(startedAt.AddMinutes(40)));
        });
    }

    [Test]
    public async Task Absolute_session_expiry_rejects_an_otherwise_valid_cookie()
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var authOptions = ValidOptions();
        authOptions.AbsoluteSessionLifetime = TimeSpan.FromMinutes(40);
        var oidcEvents = CreateOidcEvents(time, authOptions, out var oidcOptions);
        var tokenContext = TokenContext(
            oidcOptions,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-subject-1")));
        await oidcEvents.TokenValidated(tokenContext);
        time.Advance(TimeSpan.FromMinutes(41));
        var cookieContext = CookieContext(tokenContext.Principal!, tokenContext.Properties!);

        await new HipSessionCookieEvents(Options.Create(authOptions), time).ValidatePrincipal(cookieContext);

        Assert.That(cookieContext.Principal, Is.Null);
    }

    [Test]
    public async Task Validated_identity_token_expiry_does_not_shorten_the_local_idle_session()
    {
        var startedAt = new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
        var tokenExpiry = startedAt.AddMinutes(5);
        var time = new AdjustableTimeProvider(startedAt);
        var events = CreateOidcEvents(time, out var options);
        var context = TokenContext(
            options,
            ExternalPrincipal(
                new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
                new Claim(HipAuthenticationClaimTypes.Subject, "opaque-subject-1")));
        context.SecurityToken = new JwtSecurityToken(expires: tokenExpiry.UtcDateTime);

        await events.TokenValidated(context);
        time.Advance(TimeSpan.FromMinutes(20));
        var cookieContext = CookieContext(context.Principal!, context.Properties!);
        await new HipSessionCookieEvents(Options.Create(ValidOptions()), time).ValidatePrincipal(cookieContext);

        Assert.Multiple(() =>
        {
            Assert.That(context.Properties!.IssuedUtc, Is.EqualTo(time.GetUtcNow()));
            Assert.That(context.Properties.ExpiresUtc, Is.EqualTo(startedAt.AddMinutes(50)));
            Assert.That(cookieContext.ShouldRenew, Is.True);
            Assert.That(cookieContext.Principal, Is.Not.Null);
        });
    }

    [TestCase("/api/v1/admin/rules", StatusCodes.Status401Unauthorized, true)]
    [TestCase("/api/v1/admin/rules", StatusCodes.Status403Forbidden, false)]
    public async Task Cookie_redirect_events_return_status_codes_for_api_requests(
        string path,
        int expectedStatus,
        bool isLogin)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = path;
        var options = new CookieAuthenticationOptions();
        var scheme = new AuthenticationScheme(HipAuthenticationSchemes.SessionCookie, null, typeof(CookieAuthenticationHandler));
        var redirect = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            scheme,
            options,
            new AuthenticationProperties(),
            "https://hip.test/login?returnUrl=sensitive");
        var events = new HipSessionCookieEvents(Options.Create(ValidOptions()), TimeProvider.System);

        if (isLogin)
        {
            await events.RedirectToLogin(redirect);
        }
        else
        {
            await events.RedirectToAccessDenied(redirect);
        }

        Assert.Multiple(() =>
        {
            Assert.That(httpContext.Response.StatusCode, Is.EqualTo(expectedStatus));
            Assert.That(httpContext.Response.Headers.Location, Is.Empty);
        });
    }

    [Test]
    public async Task Remote_failure_redirect_is_generic_and_does_not_disclose_provider_errors()
    {
        const string sensitiveMarker = "sensitive-provider-error";
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var httpContext = new DefaultHttpContext();
        var context = new RemoteFailureContext(
            httpContext,
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            new InvalidOperationException(sensitiveMarker));

        await events.RemoteFailure(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Handled, Is.True);
            Assert.That(httpContext.Response.Headers.Location.ToString(), Is.EqualTo("/login?error=external-authentication"));
            Assert.That(httpContext.Response.Headers.Location.ToString(), Does.Not.Contain(sensitiveMarker));
        });
    }

    [Test]
    public async Task Remote_failure_logs_only_a_privacy_safe_category()
    {
        const string sensitiveMarker = "sensitive-provider-state";
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 8, 2, 12, 0, 0, TimeSpan.Zero));
        var logger = new CapturingLogger<HipOpenIdConnectEvents>();
        var events = CreateOidcEvents(time, ValidOptions(), out var options, logger);
        var context = new RemoteFailureContext(
            new DefaultHttpContext(),
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            new AuthenticationFailureException($"Correlation failed: {sensitiveMarker}"));

        await events.RemoteFailure(context);

        var entry = logger.Entries.Single();
        Assert.Multiple(() =>
        {
            Assert.That(entry.LogLevel, Is.EqualTo(LogLevel.Warning));
            Assert.That(entry.EventId, Is.EqualTo(new EventId(2101, "OidcRemoteFailure")));
            Assert.That(entry.Message, Does.Contain("Category=correlation"));
            Assert.That(entry.Message, Does.Contain("ExceptionType=AuthenticationFailureException"));
            Assert.That(entry.Message, Does.Not.Contain(sensitiveMarker));
            Assert.That(entry.Exception, Is.Null);
        });
    }

    [Test]
    public async Task Consumer_remote_failure_returns_to_the_mapped_login_page()
    {
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var httpContext = new DefaultHttpContext();
        var context = new RemoteFailureContext(
            httpContext,
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            new InvalidOperationException("provider failure"))
        {
            Properties = new AuthenticationProperties { RedirectUri = "/consumer" }
        };

        await events.RemoteFailure(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Handled, Is.True);
            Assert.That(
                httpContext.Response.Headers.Location.ToString(),
                Is.EqualTo("/login?error=external-authentication"));
        });
    }

    [TestCase("/admin/rules", "/step-up?error=unsatisfied&returnUrl=%2Fadmin%2Frules")]
    [TestCase("//evil.example/path", "/step-up?error=unsatisfied&returnUrl=%2Fadmin")]
    public async Task Step_up_remote_failure_is_generic_preserves_only_a_safe_return_and_cleans_state(
        string requestedReturnUrl,
        string expectedLocation)
    {
        const string sensitiveMarker = "sensitive-step-up-provider-error";
        var time = new AdjustableTimeProvider(new DateTimeOffset(2026, 7, 19, 12, 0, 0, TimeSpan.Zero));
        var events = CreateOidcEvents(time, out var options);
        var properties = StepUpProperties("hip-user:v1:test-actor", time.GetUtcNow().AddHours(1));
        properties.RedirectUri = requestedReturnUrl;
        var httpContext = new DefaultHttpContext();
        var context = new RemoteFailureContext(
            httpContext,
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            new InvalidOperationException(sensitiveMarker))
        {
            Properties = properties
        };

        await events.RemoteFailure(context);

        Assert.Multiple(() =>
        {
            Assert.That(context.Result?.Handled, Is.True);
            Assert.That(
                httpContext.Response.Headers.Location.ToString(),
                Is.EqualTo(expectedLocation));
            Assert.That(httpContext.Response.Headers.Location.ToString(), Does.Not.Contain(sensitiveMarker));
            Assert.That(HipStepUpAuthenticationProperties.IsStepUp(properties), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out _), Is.False);
            Assert.That(HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(properties, out _), Is.False);
        });
    }

    private static HipOpenIdConnectEvents CreateOidcEvents(
        TimeProvider time,
        out OpenIdConnectOptions oidcOptions) =>
        CreateOidcEvents(time, ValidOptions(), out oidcOptions);

    private static HipOpenIdConnectEvents CreateOidcEvents(
        TimeProvider time,
        HipProductionAuthenticationOptions authOptions,
        out OpenIdConnectOptions oidcOptions,
        ILogger<HipOpenIdConnectEvents>? logger = null)
    {
        oidcOptions = new OpenIdConnectOptions();
        var configured = Options.Create(authOptions);
        return new HipOpenIdConnectEvents(
            new HipExternalClaimsMapper(configured),
            new HipExternalAuthenticationAssuranceEvaluator(configured, time),
            configured,
            time,
            logger ?? NullLogger<HipOpenIdConnectEvents>.Instance);
    }

    private static TokenValidatedContext TokenContext(
        OpenIdConnectOptions options,
        ClaimsPrincipal principal,
        AuthenticationProperties? properties = null) =>
        new(
            new DefaultHttpContext(),
            new AuthenticationScheme(HipAuthenticationSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler)),
            options,
            principal,
            properties ?? new AuthenticationProperties());

    private static CookieValidatePrincipalContext CookieContext(
        ClaimsPrincipal principal,
        AuthenticationProperties properties)
    {
        var options = new CookieAuthenticationOptions();
        var scheme = new AuthenticationScheme(HipAuthenticationSchemes.SessionCookie, null, typeof(CookieAuthenticationHandler));
        var ticket = new AuthenticationTicket(principal, properties, HipAuthenticationSchemes.SessionCookie);
        return new CookieValidatePrincipalContext(new DefaultHttpContext(), scheme, options, ticket);
    }

    private static ClaimsPrincipal ExternalPrincipal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, HipAuthenticationSchemes.OpenIdConnect));

    private static ClaimsPrincipal AssuredPrivilegedPrincipal(DateTimeOffset authenticationTime) =>
        ExternalPrincipal(
            new Claim(HipAuthenticationClaimTypes.Issuer, "https://identity.hip.test/tenant/v2.0"),
            new Claim(HipAuthenticationClaimTypes.Subject, "opaque-step-up-subject"),
            new Claim("roles", "hip-owner"),
            new Claim("amr", "pwd"),
            new Claim("amr", "mfa"),
            new Claim(
                "auth_time",
                authenticationTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));

    private static AuthenticationProperties StepUpProperties(
        string expectedActorId,
        DateTimeOffset originalAbsoluteExpiry)
    {
        var properties = new AuthenticationProperties { RedirectUri = "/admin/rules" };
        HipStepUpAuthenticationProperties.SetStepUpMarker(properties);
        HipStepUpAuthenticationProperties.SetExpectedActorId(properties, expectedActorId);
        HipStepUpAuthenticationProperties.SetOriginalAbsoluteExpiry(properties, originalAbsoluteExpiry);
        return properties;
    }

    private static HipProductionAuthenticationOptions ValidOptions() => new()
    {
        Authority = "https://identity.hip.test/tenant/v2.0",
        ClientId = "hip-web",
        ClientSecret = "test-oidc-secret",
        RoleClaimType = "roles",
        RoleMappings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hip-owner"] = AdminRoles.Owner,
            ["hip-admin"] = AdminRoles.Admin
        },
        AcceptStandardMfaAmr = true,
        TrustedMfaAcrValues = ["urn:hip:test:mfa"],
        RecentAuthenticationLifetime = TimeSpan.FromMinutes(10),
        IdleSessionLifetime = TimeSpan.FromMinutes(30),
        AbsoluteSessionLifetime = TimeSpan.FromHours(8)
    };

    private sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset currentUtc = utcNow;

        public override DateTimeOffset GetUtcNow() => currentUtc;

        public void Advance(TimeSpan duration) => currentUtc = currentUtc.Add(duration);
    }
}
