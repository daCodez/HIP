using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Dashboard;
using HIP.Application.SiteSafety;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
        var scoring = json.RootElement.GetProperty("scoring");
        var reasonEntries = scoring.GetProperty("reasonEntries");
        var providerEvidence = json.RootElement.GetProperty("providerEvidence");
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("LimitedData"));
            Assert.That(scoring.GetProperty("modelVersion").GetString(), Is.EqualTo("hip-0301-v1"));
            Assert.That(scoring.GetProperty("contentRiskScoreHigherMeansMoreRisk").GetBoolean(), Is.True);
            Assert.That(scoring.GetProperty("canAssertPositiveTrust").GetBoolean(), Is.False);
            Assert.That(scoring.GetProperty("presentationStatus").GetString(), Is.EqualTo("LimitedTrustData"));
            Assert.That(reasonEntries.GetArrayLength(), Is.GreaterThan(0));
            Assert.That(reasonEntries.EnumerateArray().All(entry =>
                entry.GetProperty("code").GetString() is { Length: > 0 } code &&
                code == code.ToLowerInvariant()), Is.True);
            Assert.That(reasonEntries.EnumerateArray().All(entry =>
                entry.GetProperty("privacyClassification").GetString() is "PublicMetadata" or "DerivedMetadata"), Is.True);
            Assert.That(providerEvidence.GetArrayLength(), Is.GreaterThan(0));
            Assert.That(providerEvidence.EnumerateArray().All(entry =>
                entry.GetProperty("resultStatus").GetString() is "Succeeded" or "Partial" or "TimedOut" or "Failed"), Is.True);
            Assert.That(providerEvidence.EnumerateArray().All(entry =>
                entry.GetProperty("latencyMilliseconds").GetInt64() >= 0), Is.True);
            Assert.That(providerEvidence.EnumerateArray().All(entry =>
                entry.GetProperty("freshness").GetString() is "Fresh" or "Stale" or "Expired"), Is.True);
            Assert.That(providerEvidence.EnumerateArray().All(entry =>
                entry.GetProperty("privacyClassification").GetString() is "PublicDomainMetadata" or "HashedUrlMetadata" or "PrivacySafeObservedSignals"), Is.True);
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
    /// Verifies a local rules administrator can run the protected external-evidence operation.
    /// </summary>
    [Test]
    public async Task External_evidence_check_allows_local_rules_admin()
    {
        await using var baseFactory = new HipWebApplicationFactory<Program>();
        await using var factory = baseFactory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IExternalSiteEvidenceCollector>();
                services.AddSingleton<IExternalSiteEvidenceCollector, EmptyExternalSiteEvidenceCollector>();
            }));
        using var client = factory.CreateClient();
        AddRole(client, "Admin");

        var response = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-evidence/check",
            new SiteSafetyScanRequest("https://external-evidence.example/path?private=value"));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("external-evidence.example"));
            Assert.That(json.RootElement.GetProperty("providerEvidence").GetArrayLength(), Is.Zero);
        });
    }

    /// <summary>
    /// Verifies durable provider work is accepted immediately and can be read only by its requester.
    /// </summary>
    [Test]
    public async Task External_evidence_job_returns_accepted_privacy_safe_owner_scoped_status()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Admin");

        var accepted = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-evidence/jobs",
            new SiteSafetyScanRequest("https://queued-api.example/private?password=secret"));
        using var acceptedJson = await JsonDocument.ParseAsync(await accepted.Content.ReadAsStreamAsync());
        var jobId = acceptedJson.RootElement.GetProperty("jobId").GetString();
        var location = accepted.Headers.Location;
        var owned = await client.GetAsync(location);
        AddRole(client, "Owner");
        var otherOwner = await client.GetAsync(location);

        Assert.Multiple(() =>
        {
            Assert.That(accepted.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));
            Assert.That(jobId, Does.StartWith("provider-job:"));
            Assert.That(acceptedJson.RootElement.GetProperty("status").GetString(), Is.EqualTo("Pending"));
            Assert.That(acceptedJson.RootElement.GetProperty("domain").GetString(), Is.EqualTo("queued-api.example"));
            Assert.That(acceptedJson.RootElement.TryGetProperty("urlHash", out _), Is.False);
            Assert.That(acceptedJson.RootElement.TryGetProperty("requesterKeyDigest", out _), Is.False);
            Assert.That(acceptedJson.RootElement.ToString(), Does.Not.Contain("password=secret"));
            Assert.That(owned.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(otherOwner.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        });
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
            Assert.That(metadata.GetProperty("submissionTrust").GetString(), Is.EqualTo("untrusted-client"));
        });
    }

    /// <summary>
    /// Verifies anonymous Site Safety observations do not flow into authoritative Admin Dashboard cards.
    /// </summary>
    [Test]
    public async Task Anonymous_site_safety_scan_is_excluded_from_admin_dashboard()
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
        Assert.That(
            summary!.RecentScans.Any(recent => recent.Domain == domain),
            Is.False,
            "Anonymous observations must not alter authoritative dashboard aggregates.");
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

    private sealed class EmptyExternalSiteEvidenceCollector : IExternalSiteEvidenceCollector
    {
        public Task<IReadOnlyCollection<SiteSafetyEvidence>> CollectAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyCollection<SiteSafetyEvidence>>([]);
        }
    }

    /// <summary>
    /// Finds one dashboard card by key.
    /// </summary>
    /// <param name="summary">Dashboard summary.</param>
    /// <param name="key">Card key.</param>
    /// <returns>Matching dashboard card.</returns>
}
