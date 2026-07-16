using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using HIP.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminAuthorizationTests
{
    [Test]
    public async Task Admin_api_requires_auth()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Public_lookup_does_not_require_auth()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/lookup/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Public_badge_does_not_require_auth()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/badge/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Owner_can_access_protected_admin_route()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Owner");

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Readonly_cannot_approve_override()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.PostAsJsonAsync("/api/v1/admin/reputation-overrides/override-1/approve", new
        {
            ActorId = "readonly",
            Reason = "Should not approve."
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Moderator_can_review_reports()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Moderator");

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Support_cannot_manage_rules()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Support");

        var response = await client.PostAsJsonAsync("/api/v1/admin/rules/simulate", new
        {
            Rule = (object?)null,
            TestCases = Array.Empty<object>()
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Unauthorized_request_is_rejected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Readonly_can_view_external_provider_settings_enabled_for_dev_tls_by_default()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/api/v1/admin/site-safety/external-providers");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("externalProvidersEnabled").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("googleWebRisk").GetProperty("enabled").GetBoolean(), Is.False);
            Assert.That(json.RootElement.GetProperty("virusTotal").GetProperty("enabled").GetBoolean(), Is.False);
            Assert.That(json.RootElement.GetProperty("sslLabs").GetProperty("apiKey").ValueKind, Is.EqualTo(JsonValueKind.Null));
        });
    }

    /// <summary>
    /// Confirms the login page contains a real credential form without placing a password in the page.
    /// </summary>
    [Test]
    public async Task Login_page_collects_credentials_without_prefilling_password()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var html = await client.GetStringAsync("/login");

        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("name=\"email\""));
            Assert.That(html, Does.Contain("name=\"password\""));
            Assert.That(html, Does.Contain("type=\"submit\""));
            Assert.That(html, Does.Contain("__RequestVerificationToken"));
            Assert.That(Regex.IsMatch(html, "name=\"password\"[^>]*value=", RegexOptions.CultureInvariant), Is.False);
        });
    }

    /// <summary>
    /// Confirms correct local development credentials issue an admin cookie and preserve a safe return path.
    /// </summary>
    [Test]
    public async Task Valid_admin_credentials_set_browser_cookie()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await SubmitLoginAsync(client, HipWebApplicationFactory<Program>.TestAdminEmail,
            HipWebApplicationFactory<Program>.TestAdminPassword, "/admin/licenses");
        var adminHtml = await client.GetStringAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/admin/licenses"));
            Assert.That(response.Headers.TryGetValues("Set-Cookie", out var cookies), Is.True);
            Assert.That(cookies!, Has.Some.Contains("HIP_DEV_ADMIN_ROLE"));
            Assert.That(adminHtml, Does.Contain("action=\"/auth/logout\""));
        });
    }

    /// <summary>
    /// Confirms a different provider can own credential verification without changing the HTTP login contract.
    /// </summary>
    [Test]
    public async Task Authentication_provider_can_be_replaced_without_changing_login_endpoint()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
                services.AddHipAdminAuthenticationProvider<ReplacementAuthenticationProvider>()));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await SubmitLoginAsync(client, "replacement@hip.test", "replacement-test-secret", "/admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/admin"));
            Assert.That(response.Headers.TryGetValues("Set-Cookie", out var cookies), Is.True);
            Assert.That(cookies!, Has.Some.Contains("replacement-subject"));
        });
    }

    /// <summary>
    /// Confirms failed sign-in attempts use a generic response and do not create a session.
    /// </summary>
    [Test]
    public async Task Invalid_admin_credentials_do_not_set_browser_cookie()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await SubmitLoginAsync(client, HipWebApplicationFactory<Program>.TestAdminEmail,
            "wrong-password", "/admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Does.StartWith("/login?error=invalid"));
            Assert.That(response.Headers.TryGetValues("Set-Cookie", out _), Is.False);
        });
    }

    /// <summary>
    /// Confirms direct local browser navigation to the protected dashboard starts the dev login flow.
    /// </summary>
    [Test]
    public async Task Admin_dashboard_navigation_redirects_to_login()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/login?returnUrl=%2Fadmin"));
        });
    }

    /// <summary>
    /// Verifies the dev login helper rejects absolute return URLs to avoid open redirect behavior.
    /// </summary>
    [Test]
    public async Task Development_admin_login_rejects_external_return_url()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await SubmitLoginAsync(client, HipWebApplicationFactory<Program>.TestAdminEmail,
            HipWebApplicationFactory<Program>.TestAdminPassword, "https://evil.example");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/admin"));
        });
    }

    /// <summary>
    /// Verifies the old one-click administrator bypass is no longer available, even during local development.
    /// </summary>
    [Test]
    public async Task Development_admin_login_bypass_is_removed()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var response = await client.GetAsync("/dev/admin-login/Admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    /// <summary>
    /// Verifies forged dev header authentication is accepted only for local development requests.
    /// </summary>
    [Test]
    public async Task Development_header_auth_is_blocked_for_non_local_host()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/admin/audit-logs");
        request.Headers.Host = "hip.example.com";
        request.Headers.Add("X-HIP-Admin-Role", "Owner");
        request.Headers.Add("X-HIP-Admin-User", "remote-attacker");

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Development_header_auth_is_blocked_for_non_local_peer()
    {
        await using var factory = new HipWebApplicationFactory<Program>(IPAddress.Parse("203.0.113.10"));
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/admin/audit-logs");
        request.Headers.Host = "localhost";
        request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        request.Headers.Add("X-HIP-Admin-Role", "Owner");
        request.Headers.Add("X-HIP-Admin-User", "remote-attacker");

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Development_logout_is_hidden_from_non_local_peer()
    {
        await using var factory = new HipWebApplicationFactory<Program>(IPAddress.Parse("203.0.113.10"));
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        request.Headers.Host = "localhost";

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    [Test]
    public async Task Admin_can_enable_external_provider_settings()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Admin");

        var response = await client.PostAsJsonAsync("/api/v1/admin/site-safety/external-providers", new
        {
            ExternalProvidersEnabled = true,
            AllowFullUrlChecks = false,
            ProviderTimeout = "00:00:02",
            DefaultCacheDuration = "06:00:00",
            SslLabs = new { Enabled = true, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = "06:00:00" },
            GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            VirusTotal = new { Enabled = true, Endpoint = "https://example.invalid/vt", ApiKey = "dev-placeholder", AllowFullUrl = false, CacheDuration = "03:00:00" }
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("externalProvidersEnabled").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("virusTotal").GetProperty("enabled").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("virusTotal").GetProperty("apiKey").ValueKind, Is.EqualTo(JsonValueKind.Null));
    }

    /// <summary>
    /// Verifies admin provider settings are scoped by user and browser instance instead of mutating process-global defaults.
    /// </summary>
    [Test]
    public async Task Admin_external_provider_settings_are_scoped_per_user_and_instance()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var firstClient = factory.CreateClient();
        using var secondClient = factory.CreateClient();
        AddRole(firstClient, "Admin");
        AddRole(secondClient, "Admin");
        firstClient.DefaultRequestHeaders.Add("X-HIP-Instance-Id", "first-instance");
        secondClient.DefaultRequestHeaders.Add("X-HIP-Instance-Id", "second-instance");

        var update = await firstClient.PostAsJsonAsync("/api/v1/admin/site-safety/external-providers", new
        {
            ExternalProvidersEnabled = false,
            AllowFullUrlChecks = false,
            ProviderTimeout = "00:00:10",
            DefaultCacheDuration = "06:00:00",
            SslLabs = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            VirusTotal = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null }
        });

        var firstRead = await firstClient.GetAsync("/api/v1/admin/site-safety/external-providers");
        var secondRead = await secondClient.GetAsync("/api/v1/admin/site-safety/external-providers");

        Assert.Multiple(() =>
        {
            Assert.That(update.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(firstRead.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(secondRead.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        var firstJson = await JsonDocument.ParseAsync(await firstRead.Content.ReadAsStreamAsync());
        var secondJson = await JsonDocument.ParseAsync(await secondRead.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(firstJson.RootElement.GetProperty("externalProvidersEnabled").GetBoolean(), Is.False);
            Assert.That(firstJson.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.False);
            Assert.That(secondJson.RootElement.GetProperty("externalProvidersEnabled").GetBoolean(), Is.True);
            Assert.That(secondJson.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.True);
        });
    }

    [Test]
    public async Task Readonly_cannot_update_external_provider_settings()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.PostAsJsonAsync("/api/v1/admin/site-safety/external-providers", new
        {
            ExternalProvidersEnabled = true,
            AllowFullUrlChecks = false,
            SslLabs = new { Enabled = true, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null },
            VirusTotal = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = false, CacheDuration = (string?)null }
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-test-admin");
    }

    /// <summary>
    /// Loads a fresh anti-forgery token and submits the local development login form.
    /// </summary>
    private static async Task<HttpResponseMessage> SubmitLoginAsync(HttpClient client, string email, string password, string returnUrl)
    {
        var html = await client.GetStringAsync($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
        var tokenMatch = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"", RegexOptions.CultureInvariant);
        Assert.That(tokenMatch.Success, Is.True, "The login form must include an anti-forgery token.");

        return await client.PostAsync("/auth/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = password,
            ["returnUrl"] = returnUrl,
            ["__RequestVerificationToken"] = tokenMatch.Groups[1].Value
        }));
    }

    private sealed class ReplacementAuthenticationProvider : IHipAdminAuthenticationProvider
    {
        public ValueTask<HipAdminAuthenticationResult> AuthenticateAsync(
            HipAdminAuthenticationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var accepted =
                request.Email == "replacement@hip.test" &&
                request.Password == "replacement-test-secret";
            var result = accepted
                ? HipAdminAuthenticationResult.Success(
                    new HipAdminIdentity(
                        "replacement-subject",
                        request.Email,
                        "Replacement Admin",
                        AdminRoles.Owner))
                : HipAdminAuthenticationResult.Failed;
            return ValueTask.FromResult(result);
        }
    }
}
