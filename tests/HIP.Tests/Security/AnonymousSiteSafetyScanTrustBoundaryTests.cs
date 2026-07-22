extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Review;
using HIP.Application.SiteSafety;
using HIP.Domain.Risk;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

/// <summary>
/// Proves anonymous caller observations remain untrusted after HIP computes a Site Safety response.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class AnonymousSiteSafetyScanTrustBoundaryTests
{
    /// <summary>HIP.Web keeps anonymous Site Safety observations out of authoritative trust and review state.</summary>
    [Test]
    public Task Web_anonymous_site_safety_scan_remains_untrusted() =>
        AssertAnonymousSiteSafetyScanRemainsUntrustedAsync<Program>(
            "web",
            "/api/v1/public/lookup");

    /// <summary>HIP.ApiService keeps anonymous Site Safety observations out of authoritative trust and review state.</summary>
    [Test]
    public Task Api_service_anonymous_site_safety_scan_remains_untrusted() =>
        AssertAnonymousSiteSafetyScanRemainsUntrustedAsync<ApiServiceAlias::ApiServiceProgram>(
            "api",
            "/api/v1/public/lookup/domain");

    private static async Task AssertAnonymousSiteSafetyScanRemainsUntrustedAsync<TProgram>(
        string host,
        string lookupRoutePrefix)
        where TProgram : class
    {
        await using var factory = new HipWebApplicationFactory<TProgram>();
        using var client = factory.CreateClient();
        var domain = $"untrusted-observation-{host}-{Guid.NewGuid():N}.example";
        var request = new SiteSafetyScanRequest(
            $"https://{domain}/login",
            new SiteSafetyObservedSignals(
                DownloadLinks: [$"https://{domain}/setup.exe"],
                HasLoginForm: true,
                HasPasswordField: true,
                ContainsScamWording: true,
                ContainsUrgencyWording: true,
                ContainsImpersonationWording: true,
                KnownPhishingPattern: true,
                KnownMalwareIndicator: true,
                KnownAbuseReports: 20,
                DomainReputationScore: 1,
                PageReputationScore: 1,
                TrustDataAvailable: true,
                ShortenedLinkCount: 2,
                ObfuscatedLinkCount: 2,
                MatchedRiskTerms: ["FakeLogin"]),
            PluginVersion: "HIP Security Regression Test");

        using var scan = await client.PostAsJsonAsync("/api/v1/site-safety/scan", request);
        using var stored = await client.GetAsync($"/api/v1/browser/scan-results/{domain}");
        using var lookup = await client.GetAsync($"{lookupRoutePrefix}/{domain}");

        Assert.Multiple(() =>
        {
            Assert.That(scan.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(stored.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(lookup.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        using var storedJson = await JsonDocument.ParseAsync(await stored.Content.ReadAsStreamAsync());
        using var lookupJson = await JsonDocument.ParseAsync(await lookup.Content.ReadAsStreamAsync());
        var statusElement = lookupJson.RootElement.GetProperty("status");
        var lookupStatus = statusElement.ValueKind == JsonValueKind.String
            ? statusElement.GetString()
            : ((RiskStatus)statusElement.GetInt32()).ToString();
        await using var scope = factory.Services.CreateAsyncScope();
        var reviewQueue = scope.ServiceProvider.GetRequiredService<IAdminReviewQueueService>();
        var reviews = await reviewQueue.ListAsync(CancellationToken.None);
        var sandboxQueue = scope.ServiceProvider.GetRequiredService<ISandboxLinkScanQueue>();
        var sandboxRequests = await sandboxQueue.DequeueBatchAsync(20, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                storedJson.RootElement.GetProperty("privacySafeMetadata").GetProperty("submissionTrust").GetString(),
                Is.EqualTo("untrusted-client"));
            Assert.That(lookupJson.RootElement.GetProperty("dataSource").GetString(), Is.EqualTo("NoStoredData"));
            Assert.That(lookupStatus, Is.EqualTo(nameof(RiskStatus.LimitedTrustData)));
            Assert.That(lookupJson.RootElement.GetProperty("recommendedAction").GetString(), Is.EqualTo("ShowCaution"));
            Assert.That(
                reviews.Any(item => item.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)),
                Is.False,
                "Anonymous caller observations must not enqueue authoritative admin review signals.");
            Assert.That(
                sandboxRequests.Any(item => item.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase)),
                Is.False,
                "Anonymous caller observations must not enqueue privileged sandbox work.");
        });
    }
}
