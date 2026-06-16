using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminAuthorizationTests
{
    [Test]
    public async Task Admin_api_requires_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Public_lookup_does_not_require_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/lookup/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Public_badge_does_not_require_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/badge/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Owner_can_access_protected_admin_route()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Owner");

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Readonly_cannot_approve_override()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Moderator");

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Support_cannot_manage_rules()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Readonly_can_view_external_provider_settings_enabled_for_dev_tls_by_default()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
    /// Confirms local development browser login issues a dev-only admin cookie and redirects to the dashboard.
    /// </summary>
    [Test]
    public async Task Development_admin_login_sets_browser_cookie()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/dev/admin-login/Admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/admin"));
            Assert.That(response.Headers.TryGetValues("Set-Cookie", out var cookies), Is.True);
            Assert.That(cookies!, Has.Some.Contains("HIP_DEV_ADMIN_ROLE"));
        });
    }

    /// <summary>
    /// Confirms direct local browser navigation to the protected dashboard starts the dev login flow.
    /// </summary>
    [Test]
    public async Task Admin_dashboard_navigation_redirects_to_development_login()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/admin");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/dev/admin-login/Owner?returnUrl=%2Fadmin"));
        });
    }

    /// <summary>
    /// Verifies the dev login helper rejects absolute return URLs to avoid open redirect behavior.
    /// </summary>
    [Test]
    public async Task Development_admin_login_rejects_external_return_url()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var response = await client.GetAsync("/dev/admin-login/Admin?returnUrl=https%3A%2F%2Fevil.example");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.ToString(), Is.EqualTo("/admin"));
        });
    }

    /// <summary>
    /// Verifies the development login helper is invisible to non-local hosts so it cannot become a remote backdoor.
    /// </summary>
    [Test]
    public async Task Development_admin_login_is_blocked_for_non_local_host()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "/dev/admin-login/Admin");
        request.Headers.Host = "hip.example.com";

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    /// <summary>
    /// Verifies forged dev header authentication is accepted only for local development requests.
    /// </summary>
    [Test]
    public async Task Development_header_auth_is_blocked_for_non_local_host()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/admin/audit-logs");
        request.Headers.Host = "hip.example.com";
        request.Headers.Add("X-HIP-Admin-Role", "Owner");
        request.Headers.Add("X-HIP-Admin-User", "remote-attacker");

        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Admin_can_enable_external_provider_settings()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
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
}
