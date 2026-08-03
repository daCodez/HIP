using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HIP.Tests.Security;

/// <summary>
/// Exercises HIP's real Production login UI, endpoints, challenge routing, and shared cookie protection.
/// </summary>
[NonParallelizable]
public sealed class HipProductionAuthenticationEndpointTests
{
    [Test]
    public async Task Production_login_renders_external_sign_in_without_email_or_password_fields()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);

        using var response = await client.GetAsync("/login");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Continue to sign in"));
            Assert.That(html, Does.Not.Match("<input[^>]+type=\"email\""));
            Assert.That(html, Does.Not.Match("<input[^>]+type=\"password\""));
            Assert.That(html, Does.Not.Match("<input[^>]+name=\"email\""));
            Assert.That(html, Does.Not.Match("<input[^>]+name=\"password\""));
        });
    }

    [Test]
    public async Task Production_external_authentication_failure_uses_the_mapped_login_page()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);

        using var response = await client.GetAsync("/login?error=external-authentication");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("We could not complete sign-in."));
            Assert.That(html, Does.Contain("No provider details were stored by HIP."));
        });
    }

    [TestCase("/auth/login")]
    [TestCase("/auth/logout")]
    public async Task Production_authentication_posts_without_antiforgery_are_rejected(string path)
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["returnUrl"] = "/admin"
            })
        };
        using var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Production_authentication_posts_are_limited_to_four_kibibytes()
    {
        const long expectedMaximumBodyBytes = 4096;
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        var endpoints = AuthenticationPostEndpoints(factory.Services);

        Assert.Multiple(() =>
        {
            Assert.That(endpoints, Has.Length.EqualTo(3));
            Assert.That(
                endpoints.All(endpoint =>
                    endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize ==
                    expectedMaximumBodyBytes),
                Is.True);
        });
    }

    [Test]
    public async Task Production_logout_uses_the_login_rate_limit_policy()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        var logout = AuthenticationPostEndpoints(factory.Services)
            .Single(endpoint => endpoint.RoutePattern.RawText == "/auth/logout");

        Assert.That(
            logout.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName,
            Is.EqualTo(RateLimitPolicies.AdminLoginPolicy));
    }

    [Test]
    public async Task Production_step_up_is_bounded_rate_limited_and_requires_an_owner_or_admin()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        var stepUp = AuthenticationPostEndpoints(factory.Services)
            .Single(endpoint => endpoint.RoutePattern.RawText == "/auth/step-up");
        var authorizeData = stepUp.Metadata.GetOrderedMetadata<IAuthorizeData>();
        var policy = await AuthorizationPolicy.CombineAsync(
            factory.Services.GetRequiredService<IAuthorizationPolicyProvider>(),
            authorizeData);
        var roles = policy?.Requirements
            .OfType<RolesAuthorizationRequirement>()
            .SelectMany(requirement => requirement.AllowedRoles)
            .ToArray() ?? [];

        Assert.Multiple(() =>
        {
            Assert.That(
                stepUp.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName,
                Is.EqualTo(RateLimitPolicies.AdminLoginPolicy));
            Assert.That(authorizeData.Select(data => data.Policy),
                Is.EquivalentTo(new[] { AdminPolicies.CanRequestPrivilegedStepUp }));
            Assert.That(
                roles,
                Is.EquivalentTo(new[] { AdminRoles.Owner, AdminRoles.Admin }));
        });
    }

    [Test]
    public async Task Valid_production_login_challenges_the_configured_idp_with_code_and_pkce_only()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        var form = await GetAntiforgeryFormAsync(client);

        using var response = await PostAntiforgeryFormAsync(client, "/auth/login", form, "/admin");
        var location = response.Headers.Location;
        var query = QueryHelpers.ParseQuery(location!.Query);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(location.GetLeftPart(UriPartial.Path), Is.EqualTo(HipProductionAuthenticationTestHost.IdentityProviderAuthorizationEndpoint));
            Assert.That(query["response_type"].ToString(), Is.EqualTo("code"));
            Assert.That(query["code_challenge"].ToString(), Is.Not.Empty);
            Assert.That(query["code_challenge_method"].ToString(), Is.EqualTo("S256"));
            Assert.That(query["scope"].ToString(), Is.EqualTo("openid"));
            Assert.That(query["acr_values"].ToString(), Is.EqualTo("urn:hip:test:mfa"));
            Assert.That(query["prompt"].ToString(), Is.EqualTo("login"));
            Assert.That(query["max_age"].ToString(), Is.EqualTo("0"));
            Assert.That(query.ContainsKey("client_secret"), Is.False);
            Assert.That(location.Query, Does.Not.Contain("test-oidc-secret"));
        });
    }

    [TestCaseSource(nameof(UnsafeReturnUrls))]
    public async Task Unsafe_production_return_urls_are_replaced_before_oidc_state_is_created(string unsafeReturnUrl)
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        var form = await GetAntiforgeryFormAsync(client);

        using var response = await PostAntiforgeryFormAsync(client, "/auth/login", form, unsafeReturnUrl);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        var oidc = factory.Services.GetRequiredService<IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>()
            .Get(HipAuthenticationSchemes.OpenIdConnect);
        var properties = oidc.StateDataFormat.Unprotect(query["state"].ToString());

        Assert.That(properties?.RedirectUri, Is.EqualTo("/admin"));
    }

    [Test]
    public async Task Production_step_up_page_contains_an_explicit_provider_action_without_password_fields()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/step-up?returnUrl=/admin/rules");
        request.Headers.Add("Cookie", CreateSessionCookie(factory.Services));

        using var response = await client.SendAsync(request);
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Confirm identity"));
            Assert.That(html, Does.Contain("action=\"/auth/step-up\""));
            Assert.That(html, Does.Not.Match("<input[^>]+type=\"password\""));
        });
    }

    [Test]
    public async Task Production_step_up_without_antiforgery_is_rejected_for_an_authenticated_owner()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/step-up")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["returnUrl"] = "/admin/rules"
            })
        };
        request.Headers.Add("Cookie", CreateSessionCookie(factory.Services));

        using var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Valid_production_step_up_binds_actor_and_absolute_expiry_into_protected_oidc_state()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        var sessionCookie = CreateSessionCookie(factory.Services);
        var form = await GetAntiforgeryFormAsync(client, sessionCookie);

        using var response = await PostAntiforgeryFormAsync(
            client,
            "/auth/step-up",
            form,
            "/admin/rules",
            sessionCookie);
        var location = response.Headers.Location!;
        var query = QueryHelpers.ParseQuery(location.Query);
        var oidc = factory.Services
            .GetRequiredService<IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>()
            .Get(HipAuthenticationSchemes.OpenIdConnect);
        var properties = oidc.StateDataFormat.Unprotect(query["state"].ToString());

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(query["prompt"].ToString(), Is.EqualTo("login"));
            Assert.That(query["max_age"].ToString(), Is.EqualTo("0"));
            Assert.That(query["acr_values"].ToString(), Is.EqualTo("urn:hip:test:mfa"));
            Assert.That(properties?.RedirectUri, Is.EqualTo("/admin/rules"));
            Assert.That(properties is not null && HipStepUpAuthenticationProperties.IsStepUp(properties), Is.True);
            Assert.That(
                properties is not null &&
                HipStepUpAuthenticationProperties.TryGetExpectedActorId(properties, out var actorId) &&
                actorId == "hip-user:v1:test-actor",
                Is.True);
            Assert.That(
                properties is not null &&
                HipStepUpAuthenticationProperties.TryGetOriginalAbsoluteExpiry(properties, out var absoluteExpiry) &&
                absoluteExpiry > DateTimeOffset.UtcNow.AddHours(7),
                Is.True);
            Assert.That(location.Query, Does.Not.Contain("test-oidc-secret"));
        });
    }

    [Test]
    public async Task Forged_development_headers_and_cookies_cannot_authenticate_in_production()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/admin/roles");
        request.Headers.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, AdminRoles.Owner);
        request.Headers.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, "forged-owner");
        request.Headers.Add(HipDevHeaderAuthenticationHandler.ConsumerHeaderName, "forged-consumer");
        request.Headers.Add(
            "Cookie",
            $"{HipDevHeaderAuthenticationHandler.DevAdminRoleCookieName}={AdminRoles.Owner}; " +
            $"{HipDevHeaderAuthenticationHandler.DevAdminUserCookieName}=forged-owner");

        using var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(response.Headers.Location, Is.Null);
        });
    }

    [Test]
    public async Task Tampered_production_session_cookie_cannot_authenticate_or_trigger_an_api_redirect()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/admin/roles");
        request.Headers.Add("Cookie", "__Host-HIP.Session=forged-and-not-data-protected");

        using var response = await client.SendAsync(request);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(response.Headers.Location, Is.Null);
        });
    }

    [Test]
    public async Task Anonymous_api_stays_401_while_protected_page_challenges_oidc()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);

        using var apiResponse = await client.GetAsync("/api/v1/admin/roles");
        using var pageResponse = await client.GetAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(apiResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(apiResponse.Headers.Location, Is.Null);
            Assert.That(pageResponse.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(
                pageResponse.Headers.Location?.GetLeftPart(UriPartial.Path),
                Is.EqualTo(HipProductionAuthenticationTestHost.IdentityProviderAuthorizationEndpoint));
        });
    }

    [Test]
    public async Task Production_logout_clears_session_cookie_and_starts_generic_oidc_signout()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        using var client = CreateClient(factory);
        var sessionCookie = CreateSessionCookie(factory.Services);
        var form = await GetAntiforgeryFormAsync(client, sessionCookie);

        using var response = await PostAntiforgeryFormAsync(
            client,
            "/auth/logout",
            form,
            "/login",
            sessionCookie);
        var setCookies = response.Headers.GetValues("Set-Cookie").ToArray();
        var logoutQuery = QueryHelpers.ParseQuery(response.Headers.Location!.Query);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(setCookies.Any(value =>
                value.StartsWith("__Host-HIP.Session=", StringComparison.Ordinal) &&
                value.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(
                response.Headers.Location?.GetLeftPart(UriPartial.Path),
                Is.EqualTo(HipProductionAuthenticationTestHost.IdentityProviderEndSessionEndpoint));
            Assert.That(logoutQuery["client_id"].ToString(), Is.EqualTo("hip-web-test"));
            Assert.That(
                logoutQuery["post_logout_redirect_uri"].ToString(),
                Is.EqualTo("https://localhost/signout-callback-oidc"));
            Assert.That(logoutQuery.ContainsKey("id_token_hint"), Is.False);
            Assert.That(response.Headers.Location?.Query, Does.Not.Contain("secret").IgnoreCase);
        });
    }

    [Test]
    public async Task Shared_key_ring_certificate_and_application_name_interoperate_but_other_apps_do_not()
    {
        await using var factory = await HipProductionAuthenticationTestHost.CreateAsync();
        var producer = CookieFormat(factory.Services);
        var ticket = SessionTicket();
        var protectedTicket = producer.Protect(ticket);

        using var matchingProvider = BuildCookieProvider(factory, "HIP.Web");
        using var isolatedProvider = BuildCookieProvider(factory, "HIP.Other");
        var matchingTicket = CookieFormat(matchingProvider).Unprotect(protectedTicket);
        var isolatedTicket = CookieFormat(isolatedProvider).Unprotect(protectedTicket);

        Assert.Multiple(() =>
        {
            Assert.That(matchingTicket?.Principal.FindFirstValue(ClaimTypes.NameIdentifier), Is.EqualTo("hip-user:v1:test-actor"));
            Assert.That(isolatedTicket, Is.Null);
        });
    }

    private static IEnumerable<string> UnsafeReturnUrls()
    {
        yield return "//evil.example/path";
        yield return @"/admin\..\evil";
        yield return "/admin\u0001/settings";
        yield return "/" + new string('a', 2049);
    }

    private static HttpClient CreateClient(HipProductionAuthenticationTestHost factory) =>
        factory.CreateClient();

    private static RouteEndpoint[] AuthenticationPostEndpoints(IServiceProvider services) =>
        services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText is "/auth/login" or "/auth/logout" or "/auth/step-up")
            .Where(endpoint => endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods
                .Contains(HttpMethods.Post, StringComparer.OrdinalIgnoreCase) == true)
            .ToArray();

    private static async Task<AntiforgeryForm> GetAntiforgeryFormAsync(
        HttpClient client,
        string? additionalCookie = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login");
        if (!string.IsNullOrWhiteSpace(additionalCookie))
        {
            request.Headers.Add("Cookie", additionalCookie);
        }

        using var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        var inputTag = Regex.Match(
            html,
            "<input\\b[^>]*\\bname=\"__RequestVerificationToken\"[^>]*>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Value;
        var token = WebUtility.HtmlDecode(Regex.Match(
            inputTag,
            "\\bvalue=\"([^\"]+)\"",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Groups[1].Value);
        var antiforgeryCookie = response.Headers.GetValues("Set-Cookie")
            .Select(value => value.Split(';', 2)[0])
            .Single(value => value.StartsWith(".AspNetCore.Antiforgery.", StringComparison.Ordinal));
        Assert.That(token, Is.Not.Empty, "The production login page must render an antiforgery request token.");
        return new AntiforgeryForm(token, antiforgeryCookie);
    }

    private static async Task<HttpResponseMessage> PostAntiforgeryFormAsync(
        HttpClient client,
        string path,
        AntiforgeryForm form,
        string returnUrl,
        string? additionalCookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = form.RequestToken,
                ["returnUrl"] = returnUrl
            })
        };
        request.Headers.Add(
            "Cookie",
            string.IsNullOrWhiteSpace(additionalCookie)
                ? form.Cookie
                : $"{form.Cookie}; {additionalCookie}");
        return await client.SendAsync(request);
    }

    private static string CreateSessionCookie(IServiceProvider services)
    {
        var protectedTicket = CookieFormat(services).Protect(SessionTicket());
        return $"__Host-HIP.Session={protectedTicket}";
    }

    private static AuthenticationTicket SessionTicket()
    {
        var now = DateTimeOffset.UtcNow;
        var properties = new AuthenticationProperties
        {
            IssuedUtc = now,
            ExpiresUtc = now.AddMinutes(30),
            AllowRefresh = true
        };
        properties.Items[".hip.absolute_expires_utc_ticks"] = now.AddHours(8).UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "hip-user:v1:test-actor"),
            new Claim(HipAuthenticationClaimTypes.ActorId, "hip-user:v1:test-actor"),
            new Claim(HipAuthenticationClaimTypes.ConsumerId, "hip-user:v1:test-actor"),
            new Claim(
                HipAuthenticationClaimTypes.MultiFactorAuthenticated,
                bool.TrueString.ToLowerInvariant(),
                ClaimValueTypes.Boolean),
            new Claim(
                HipAuthenticationClaimTypes.AuthenticationTime,
                now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64),
            new Claim(ClaimTypes.Role, AdminRoles.Owner)
        ],
            HipAuthenticationSchemes.SessionCookie,
            ClaimTypes.NameIdentifier,
            ClaimTypes.Role));
        return new AuthenticationTicket(principal, properties, HipAuthenticationSchemes.SessionCookie);
    }

    private static ISecureDataFormat<AuthenticationTicket> CookieFormat(IServiceProvider services) =>
        services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(HipAuthenticationSchemes.SessionCookie)
            .TicketDataFormat;

    private static ServiceProvider BuildCookieProvider(
        HipProductionAuthenticationTestHost factory,
        string applicationName)
    {
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            factory.CertificatePath,
            HipProductionAuthenticationTestHost.CertificatePassword,
            X509KeyStorageFlags.EphemeralKeySet);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(certificate);
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(factory.KeyRingDirectoryPath))
            .ProtectKeysWithCertificate(certificate)
            .SetApplicationName(applicationName);
        services.AddAuthentication().AddCookie(HipAuthenticationSchemes.SessionCookie);
        return services.BuildServiceProvider();
    }

    private sealed record AntiforgeryForm(string RequestToken, string Cookie);
}
