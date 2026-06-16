using System.Net;
using System.Net.Http.Json;
using HIP.Application.Platforms;
using HIP.Domain.Reporting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies the admin platform page shows configured integrations without inventing live connector data.
/// </summary>
public sealed class AdminPlatformConnectionsPageTests
{
    /// <summary>
    /// Verifies authorized admins can load the platform connection page.
    /// </summary>
    [Test]
    public async Task Platform_connections_page_loads_for_admin()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/platforms");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Platform Connections"));
            Assert.That(html, Does.Contain("Connect Platform"));
        });
    }

    /// <summary>
    /// Verifies Discord is visible as a configured platform foundation without claiming live traffic.
    /// </summary>
    [Test]
    public async Task Platform_connections_page_shows_truthful_discord_state()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/platforms");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Discord"));
            Assert.That(html, Does.Contain("message platform"));
            Assert.That(
                html.Contains("No fake Discord traffic shown", StringComparison.Ordinal)
                || html.Contains("Ready for live Discord connector submissions", StringComparison.Ordinal),
                Is.EqualTo(true));
        });
    }

    /// <summary>
    /// Verifies the Discord row documents the privacy boundary for future message-platform ingestion.
    /// </summary>
    [Test]
    public async Task Platform_connections_page_shows_discord_privacy_safe_capabilities()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);

        var response = await client.GetAsync("/admin/platforms");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Sender hash only"));
            Assert.That(html, Does.Contain("URL and domain reports"));
            Assert.That(html, Does.Contain("No message body storage"));
            Assert.That(html, Does.Contain("Safety page routing ready"));
        });
    }

    /// <summary>
    /// Verifies reports can classify Discord distinctly without changing existing platform values.
    /// </summary>
    [Test]
    public void Report_platform_includes_stable_discord_value()
    {
        Assert.Multiple(() =>
        {
            Assert.That((int)ReportPlatform.FileDownload, Is.EqualTo(7));
            Assert.That((int)ReportPlatform.Discord, Is.EqualTo(8));
        });
    }

    /// <summary>
    /// Verifies admins can configure Discord through the protected platform API without exposing raw secrets.
    /// </summary>
    [Test]
    public async Task Discord_platform_api_connects_without_returning_raw_secrets()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddAdmin(client);
        var request = new ConnectDiscordPlatformRequest(
            "123456789012345678",
            "HIP Test Server",
            "223456789012345678",
            "323456789012345678",
            "https://discord.com/api/webhooks/123/secret",
            "raw-bot-token");

        var response = await client.PostAsJsonAsync("/api/v1/admin/platforms/discord/connect", request);
        var json = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(json, Does.Contain("\"status\":\"Connected\""));
            Assert.That(json, Does.Contain("\"webhookUrlConfigured\":true"));
            Assert.That(json, Does.Contain("\"botTokenConfigured\":true"));
            Assert.That(json, Does.Not.Contain("raw-bot-token"));
            Assert.That(json, Does.Not.Contain("discord.com/api/webhooks"));
        });
    }

    /// <summary>
    /// Verifies read-only admins can view platform state but cannot connect Discord.
    /// </summary>
    [Test]
    public async Task Discord_platform_api_rejects_readonly_connect()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "ReadOnly");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "readonly-platform-test");
        var request = new ConnectDiscordPlatformRequest("123456789012345678", null, null, null, null, null);

        var response = await client.PostAsJsonAsync("/api/v1/admin/platforms/discord/connect", request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    /// <summary>
    /// Adds the development admin headers required by the local MVP authorization handler.
    /// </summary>
    /// <param name="client">HTTP client used by the test.</param>
    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-platform-test");
    }
}
