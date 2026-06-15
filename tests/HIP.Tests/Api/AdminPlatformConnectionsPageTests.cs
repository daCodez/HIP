using System.Net;
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
    public async Task Platform_connections_page_shows_discord_as_configured_not_connected()
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
            Assert.That(html, Does.Contain("Not connected yet"));
            Assert.That(html, Does.Contain("configured"));
            Assert.That(html, Does.Contain("no live Discord connector has submitted HIP data yet"));
            Assert.That(html, Does.Contain("No fake Discord traffic shown"));
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
    /// Adds the development admin headers required by the local MVP authorization handler.
    /// </summary>
    /// <param name="client">HTTP client used by the test.</param>
    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-platform-test");
    }
}
