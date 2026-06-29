using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Dashboard;
using HIP.Application.SiteSafety;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

/// <summary>
/// API tests for the versioned HIP Site Safety Scan endpoint.
/// </summary>
[TestFixture]
public sealed class SiteSafetyApiTests
{
    /// <summary>
    /// Verifies the v1 API returns public-safe scan data for a valid public URL.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_v1_route_returns_scan_result()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest("https://example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("LimitedData"));
            Assert.That(json.RootElement.TryGetProperty("pageText", out _), Is.False);
            Assert.That(json.RootElement.TryGetProperty("formValues", out _), Is.False);
        });
    }

    /// <summary>
    /// Verifies localhost and internal URLs are rejected to avoid SSRF abuse.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_rejects_localhost_url()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest("http://localhost:5123"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Verifies a live Site Safety scan is saved through the existing privacy-safe browser scan result store.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_saves_privacy_safe_scan_result()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"live-storage-{Guid.NewGuid():N}.com";

        var scan = await client.PostAsJsonAsync("/api/v1/site-safety/scan", RiskyScanRequest(domain));
        var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");

        Assert.Multiple(() =>
        {
            Assert.That(scan.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        var json = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        var metadata = json.RootElement.GetProperty("privacySafeMetadata");
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo(domain));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("HighRisk").Or.EqualTo("Suspicious").Or.EqualTo("Dangerous"));
            Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
            Assert.That(metadata.GetProperty("source").GetString(), Is.EqualTo("SiteSafetyScan"));
            Assert.That(metadata.GetProperty("targetType").GetString(), Is.EqualTo("Url"));
            Assert.That(metadata.GetProperty("providerNames").GetString(), Does.Contain("BrowserObservedSignalProvider"));
            Assert.That(metadata.GetProperty("matchedRuleIds").GetString(), Is.Not.Empty);
            Assert.That(metadata.GetProperty("scannedAtUtc").GetString(), Is.Not.Empty);
        });
    }

    /// <summary>
    /// Verifies saved Site Safety scans flow into the Admin Dashboard live-data cards.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_is_available_to_admin_dashboard()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"dashboard-live-{Guid.NewGuid():N}.com";

        var scan = await client.PostAsJsonAsync("/api/v1/site-safety/scan", RiskyScanRequest(domain));
        AddRole(client, "Owner");
        var dashboard = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.Multiple(() =>
        {
            Assert.That(scan.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        var summary = await dashboard.Content.ReadFromJsonAsync<AdminDashboardSummary>();
        Assert.That(summary, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(summary!.HasScanData, Is.True);
            Assert.That(Card(summary, "totalScans").Value, Is.GreaterThanOrEqualTo(1));
            Assert.That(summary.RecentScans.Any(recent => recent.Domain == domain), Is.True);
        });
    }

    /// <summary>
    /// Verifies persisted scan output never exposes raw URL query secrets or private content fields.
    /// </summary>
    [Test]
    public async Task Stored_site_safety_scan_does_not_expose_private_url_or_private_fields()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"privacy-live-{Guid.NewGuid():N}.com";

        await client.PostAsJsonAsync("/api/v1/site-safety/scan", RiskyScanRequest(domain, "https", "/login?token=secret-password"));
        var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");
        var body = await stored.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Not.Contain("token=secret-password"));
            Assert.That(body, Does.Not.Contain("pageUrl"));
            Assert.That(body, Does.Not.Contain("pageUrlHash"));
            Assert.That(body, Does.Not.Contain("pageText"));
            Assert.That(body, Does.Not.Contain("formValues"));
            Assert.That(body, Does.Not.Contain("cookie"));
        });
    }

    /// <summary>
    /// Creates a privacy-safe scan request with structural signals that should produce live dashboard data.
    /// </summary>
    /// <param name="domain">Domain under test.</param>
    /// <param name="scheme">URL scheme.</param>
    /// <param name="path">URL path and query used for hashing-only storage checks.</param>
    /// <returns>Site Safety scan request.</returns>
    private static SiteSafetyScanRequest RiskyScanRequest(string domain, string scheme = "https", string path = "/login") =>
        new(
            $"{scheme}://{domain}{path}",
            new SiteSafetyObservedSignals(
                RedirectChain: [$"{scheme}://{domain}/start", $"{scheme}://{domain}/login"],
                ExternalScriptUrls: [$"{scheme}://cdn.{domain}/app.js"],
                DownloadLinks: [$"{scheme}://{domain}/setup.exe"],
                HasLoginForm: true,
                HasPasswordField: true,
                KnownPhishingPattern: true,
                ShortenedLinkCount: 1,
                ObfuscatedLinkCount: 1,
                MatchedRiskTerms: ["FakeLogin"]));

    /// <summary>
    /// Adds the development admin role headers used by protected dashboard endpoints in tests.
    /// </summary>
    /// <param name="client">HTTP client.</param>
    /// <param name="role">Admin role to apply.</param>
    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-Role");
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-User");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-site-safety-test");
    }

    /// <summary>
    /// Finds one dashboard card by key.
    /// </summary>
    /// <param name="summary">Dashboard summary.</param>
    /// <param name="key">Card key.</param>
    /// <returns>Matching dashboard card.</returns>
    private static AdminDashboardCard Card(AdminDashboardSummary summary, string key) =>
        summary.Cards.Single(card => card.Key == key);
}
