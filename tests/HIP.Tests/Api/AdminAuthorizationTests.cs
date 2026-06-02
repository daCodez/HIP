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
    public async Task Readonly_can_view_external_provider_settings()
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
        });
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
