extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Application.SiteSafety;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies the standalone Aspire API service exposes the browser plugin endpoints used by the extension.
/// </summary>
[TestFixture]
public sealed class BrowserPluginApiServiceTests
{
    /// <summary>
    /// Confirms the browser extension can score the active site through HIP.ApiService instead of needing HIP.Web.
    /// </summary>
    [Test]
    public async Task Api_service_score_site_endpoint_returns_score_status_and_reasons()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/score-site", new BrowserScoreSiteRequest(
            "https://example.com",
            "example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        Assert.That(json.RootElement.GetProperty("status").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
    }

    /// <summary>
    /// Confirms the browser extension can scan links through HIP.ApiService and receive safety routing decisions.
    /// </summary>
    [Test]
    public async Task Api_service_scan_links_endpoint_returns_link_risk_results()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-links", new BrowserScanLinksRequest(
            "https://example.com",
            ["https://example.com/about", "https://bit.ly/example"]));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var results = json.RootElement.GetProperty("results");

        Assert.That(results.GetArrayLength(), Is.EqualTo(2));
        Assert.That(results[0].GetProperty("recommendedAction").GetString(), Is.EqualTo("Allow"));
        Assert.That(results[1].GetProperty("recommendedAction").GetString(), Is.EqualTo("RouteToSafetyPage"));
    }

    /// <summary>
    /// Confirms the popup's Site Safety panel can call HIP.ApiService without receiving a route-not-found error.
    /// </summary>
    [Test]
    public async Task Api_service_site_safety_scan_endpoint_returns_public_safe_scan_result()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest(
            "https://example.com",
            new SiteSafetyObservedSignals(HasLoginForm: true, HasPasswordField: true)));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        Assert.That(json.RootElement.GetProperty("status").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.TryGetProperty("domainTrustScore", out _), Is.True);
        Assert.That(json.RootElement.ToString().Contains("password="), Is.False);
    }

    /// <summary>
    /// Confirms the Aspire API service actively persists Site Safety scan output through the browser scan store.
    /// </summary>
    /// <remarks>
    /// The browser extension calls HIP.ApiService during normal browsing, so this test proves the API host writes
    /// privacy-safe scan summaries to the configured repository instead of only returning transient scan data.
    /// </remarks>
    [Test]
    public async Task Api_service_site_safety_scan_persists_live_scan_summary()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();
        var domain = $"api-live-scan-{Guid.NewGuid():N}.com";

        var scan = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest(
            $"https://{domain}/login?token=secret-password",
            new SiteSafetyObservedSignals(
                DownloadLinks: [$"https://{domain}/setup.exe"],
                HasLoginForm: true,
                HasPasswordField: true,
                KnownPhishingPattern: true,
                ShortenedLinkCount: 1,
                ObfuscatedLinkCount: 1,
                MatchedRiskTerms: ["FakeLogin"]),
            PluginVersion: "HIP Plugin v0.1.0-dev"));
        var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");

        Assert.Multiple(() =>
        {
            Assert.That(scan.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        var json = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        var serialized = json.RootElement.ToString();
        var metadata = json.RootElement.GetProperty("privacySafeMetadata");
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo(domain));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("Dangerous").Or.EqualTo("HighRisk").Or.EqualTo("Suspicious"));
            Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Is.Not.Empty);
            Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
            Assert.That(metadata.GetProperty("source").GetString(), Is.EqualTo("SiteSafetyScan"));
            Assert.That(metadata.GetProperty("pluginVersion").GetString(), Is.EqualTo("HIP Plugin v0.1.0-dev"));
            Assert.That(metadata.GetProperty("domainTrustScore").GetString(), Is.Not.Empty);
            Assert.That(metadata.GetProperty("pageTrustScore").GetString(), Is.Not.Empty);
            Assert.That(metadata.GetProperty("contentRiskScore").GetString(), Is.Not.Empty);
            Assert.That(metadata.GetProperty("providerNames").GetString(), Does.Contain("BrowserObservedSignalProvider"));
            Assert.That(serialized, Does.Not.Contain("token=secret-password"));
            Assert.That(serialized, Does.Not.Contain("pageText"));
            Assert.That(serialized, Does.Not.Contain("formValues"));
            Assert.That(serialized, Does.Not.Contain("password=secret"));
        });
    }

    /// <summary>
    /// Verifies browser-instance provider settings cannot be changed unless the host explicitly opts in.
    /// </summary>
    [Test]
    public async Task Api_service_provider_preferences_reject_public_writes_by_default()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Instance-Id", "api-first-instance");

        var update = await client.PostAsJsonAsync("/api/v1/site-safety/external-providers", ProviderPreferencePayload(false));

        Assert.That(update.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    /// <summary>
    /// Verifies browser-instance provider settings remain scoped when a local/dev host explicitly enables client writes.
    /// </summary>
    [Test]
    public async Task Api_service_provider_preferences_are_scoped_per_browser_instance_when_enabled()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, configuration) =>
                {
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["HipSecurity:AllowClientProviderPreferenceWrites"] = "true"
                    });
                });
            });
        using var firstClient = factory.CreateClient();
        using var secondClient = factory.CreateClient();
        firstClient.DefaultRequestHeaders.Add("X-HIP-Instance-Id", "api-first-instance");
        secondClient.DefaultRequestHeaders.Add("X-HIP-Instance-Id", "api-second-instance");

        var update = await firstClient.PostAsJsonAsync("/api/v1/site-safety/external-providers", ProviderPreferencePayload(false));

        var firstRead = await firstClient.GetAsync("/api/v1/site-safety/external-providers");
        var secondRead = await secondClient.GetAsync("/api/v1/site-safety/external-providers");

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
            Assert.That(firstJson.RootElement.GetProperty("allowFullUrlChecks").GetBoolean(), Is.False);
            Assert.That(firstJson.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.False);
            Assert.That(firstJson.RootElement.GetProperty("sslLabs").GetProperty("endpoint").ValueKind, Is.EqualTo(JsonValueKind.Null));
            Assert.That(firstJson.RootElement.GetProperty("sslLabs").GetProperty("apiKey").ValueKind, Is.EqualTo(JsonValueKind.Null));
            Assert.That(secondJson.RootElement.GetProperty("externalProvidersEnabled").GetBoolean(), Is.True);
            Assert.That(secondJson.RootElement.GetProperty("sslLabs").GetProperty("enabled").GetBoolean(), Is.True);
        });
    }

    /// <summary>
    /// Builds a provider-preference request that intentionally includes unsafe fields to prove the API strips them.
    /// </summary>
    /// <param name="enabled">Whether the scoped external providers should be enabled.</param>
    /// <returns>Anonymous JSON payload for the provider preference endpoint.</returns>
    private static object ProviderPreferencePayload(bool enabled) => new
    {
        ExternalProvidersEnabled = enabled,
        AllowFullUrlChecks = true,
        ProviderTimeout = "00:00:10",
        DefaultCacheDuration = "06:00:00",
        SslLabs = new { Enabled = enabled, Endpoint = "http://attacker.invalid", ApiKey = "secret", AllowFullUrl = true, CacheDuration = (string?)null },
        GoogleWebRisk = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = true, CacheDuration = (string?)null },
        VirusTotal = new { Enabled = false, Endpoint = "", ApiKey = "", AllowFullUrl = true, CacheDuration = (string?)null }
    };
}
