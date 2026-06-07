using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Tests the browser scan result API contract used by the Chromium extension.
/// </summary>
[TestFixture]
public sealed class BrowserScanResultApiTests
{
    /// <summary>
    /// Verifies the v1 browser endpoint accepts and stores a privacy-safe scan result.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_saves_result()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("saved").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("lastCheckedUtc").GetDateTimeOffset(), Is.Not.EqualTo(default(DateTimeOffset)));
        });
    }

    /// <summary>
    /// Verifies the latest scan result can be retrieved by normalized domain.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_returns_latest_result_by_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());
        var response = await client.GetAsync("/api/v1/browser/scan-results/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.EqualTo(84));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("Trusted"));
            Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
            Assert.That(json.RootElement.GetProperty("linksScanned").GetInt32(), Is.EqualTo(42));
        });
    }

    /// <summary>
    /// Verifies newer browser plugin builds can submit a URL hash without requiring HIP to store a raw full URL.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_accepts_client_url_hash_and_plugin_version()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"hashed-scan-{Guid.NewGuid():N}.com";

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with
        {
            Domain = domain,
            PageUrl = null,
            PageUrlHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            PluginVersion = "HIP Plugin v0.1.0-dev",
            PrivacySafeMetadata = new Dictionary<string, string>
            {
                ["isHttps"] = "true",
                ["loginFormsDetected"] = "1",
                ["passwordFieldsDetected"] = "1",
                ["paymentFieldsDetected"] = "1",
                ["downloadCandidates"] = "2",
                ["shortenedLinkCandidates"] = "1",
                ["redirectCandidates"] = "1"
            }
        });
        var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        var json = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        var metadata = json.RootElement.GetProperty("privacySafeMetadata");
        Assert.Multiple(() =>
        {
            Assert.That(metadata.GetProperty("pluginVersion").GetString(), Is.EqualTo("HIP Plugin v0.1.0-dev"));
            Assert.That(metadata.GetProperty("isHttps").GetString(), Is.EqualTo("true"));
            Assert.That(metadata.GetProperty("loginFormsDetected").GetString(), Is.EqualTo("1"));
            Assert.That(metadata.GetProperty("passwordFieldsDetected").GetString(), Is.EqualTo("1"));
            Assert.That(metadata.GetProperty("paymentFieldsDetected").GetString(), Is.EqualTo("1"));
            Assert.That(metadata.GetProperty("downloadCandidates").GetString(), Is.EqualTo("2"));
            Assert.That(metadata.GetProperty("shortenedLinkCandidates").GetString(), Is.EqualTo("1"));
            Assert.That(metadata.GetProperty("redirectCandidates").GetString(), Is.EqualTo("1"));
        });
    }

    /// <summary>
    /// Verifies malformed URL hashes are rejected instead of being trusted as safe storage keys.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_rejects_invalid_url_hash()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with
        {
            PageUrl = null,
            PageUrlHash = "sha256:not-a-real-hash"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Verifies the retrieve response avoids private URL, page text, and form content fields.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_does_not_expose_private_fields()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());
        var response = await client.GetAsync("/api/v1/browser/scan-results/example.com");
        var json = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Not.Contain("pageUrl"));
            Assert.That(json, Does.Not.Contain("pageUrlHash"));
            Assert.That(json, Does.Not.Contain("pageText"));
            Assert.That(json, Does.Not.Contain("formContents"));
            Assert.That(json, Does.Not.Contain("token=secret"));
            Assert.That(json, Does.Not.Contain("password=secret"));
        });
    }

    /// <summary>
    /// Verifies invalid domains are rejected by the scan result API.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_rejects_invalid_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Domain = "bad domain" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Verifies invalid scores are rejected by the scan result API.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_rejects_invalid_score()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Score = -1 });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Verifies public lookup uses the stored browser scan result and includes source and count fields.
    /// </summary>
    [Test]
    public async Task Public_lookup_uses_stored_browser_scan_result_when_available()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"stored-scan-{Guid.NewGuid():N}.com";

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Domain = domain, PageUrl = $"https://{domain}/page?token=secret" });
        var response = await client.GetAsync($"/api/v1/public/lookup/{domain}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo(domain));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.Not.EqualTo("Trusted"));
            Assert.That(json.RootElement.GetProperty("riskLevel").GetString(), Is.Not.EqualTo("Trusted"));
            Assert.That(json.RootElement.GetProperty("domainTrustScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("pageTrustScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("contentRiskScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("finalHipScoreExplanation").GetString(), Is.Not.Empty);
            Assert.That(json.RootElement.GetProperty("dataSource").GetString(), Is.EqualTo("BrowserPluginScan"));
            Assert.That(json.RootElement.GetProperty("linksScanned").GetInt32(), Is.EqualTo(42));
            Assert.That(json.RootElement.GetProperty("riskyLinksFound").GetInt32(), Is.EqualTo(2));
            Assert.That(json.RootElement.GetProperty("dangerousLinksFound").GetInt32(), Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Verifies public lookup returns an explicit no-data state before HIP has scanned a domain.
    /// </summary>
    [Test]
    public async Task Public_lookup_returns_unknown_when_no_stored_scan_exists()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"no-scan-{Guid.NewGuid():N}.com";

        var response = await client.GetAsync($"/api/v1/public/lookup/{domain}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("LimitedTrustData"));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(45, 60));
            Assert.That(json.RootElement.GetProperty("dataSource").GetString(), Is.EqualTo("NoStoredData"));
            Assert.That(json.RootElement.GetProperty("message").GetString(), Does.Contain("not scanned"));
            Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Is.EqualTo("ShowCaution"));
        });
    }

    /// <summary>
    /// Verifies public lookup does not expose hashed URLs, raw URLs, or identity fields from stored browser scans.
    /// </summary>
    [Test]
    public async Task Public_lookup_does_not_expose_private_scan_fields()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var domain = $"privacy-scan-{Guid.NewGuid():N}.com";

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Domain = domain, PageUrl = $"https://{domain}/page?token=secret" });
        var response = await client.GetAsync($"/api/v1/public/lookup/{domain}");
        var json = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Not.Contain("pageUrl"));
            Assert.That(json, Does.Not.Contain("pageUrlHash"));
            Assert.That(json, Does.Not.Contain("token=secret"));
            Assert.That(json, Does.Not.Contain("userIdentity"));
        });
    }

    /// <summary>
    /// Creates a valid browser scan result request for API tests.
    /// </summary>
    /// <returns>A valid privacy-safe scan result request.</returns>
    private static BrowserScanResultSaveRequest ValidRequest() =>
        new(
            "example.com",
            "https://example.com/page?token=secret",
            84,
            "Trusted",
            "Trusted",
            ["No risky links found"],
            42,
            2,
            2,
            0,
            "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal",
                ["apiStatus"] = "Available"
            });
}
