using System.Net;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Scans;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Tests the admin scan details API, page route, and privacy-safe detail composition.
/// </summary>
[TestFixture]
public sealed class AdminScanDetailsTests
{
    /// <summary>
    /// Verifies the admin details service exposes layered scores, matched rules, provider evidence, feedback, and review state.
    /// </summary>
    [Test]
    public async Task Detail_service_returns_privacy_safe_scan_explanation()
    {
        var scan = StoredScan();
        var scanRepository = new InMemoryBrowserScanResultRepository();
        await scanRepository.SaveAsync(scan, CancellationToken.None);
        var feedbackService = new WeightedFeedbackAggregationService(new InMemoryWeightedFeedbackRepository());
        await feedbackService.SubmitAsync(new WeightedFeedbackSubmission(scan.Domain, HipFeedbackType.LooksSuspicious, HipFeedbackSource.BrowserPluginBanner, ReporterTrustLevel.Trusted, DateTimeOffset.UtcNow, scan.PageUrlHash), CancellationToken.None);
        var reviewRepository = new InMemoryAdminReviewQueueRepository();
        await reviewRepository.SaveAsync(Review(scan), CancellationToken.None);
        var service = new AdminScanDetailService(scanRepository, new StubScanner(), feedbackService, reviewRepository);

        var detail = await service.GetAsync(scan.ScanResultId, CancellationToken.None);

        Assert.That(detail, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(detail!.Domain, Is.EqualTo(scan.Domain));
            Assert.That(detail.UrlHash, Is.EqualTo(scan.PageUrlHash));
            Assert.That(detail.DomainTrustScore, Is.EqualTo(58));
            Assert.That(detail.PageTrustScore, Is.EqualTo(34));
            Assert.That(detail.ContentRiskScore, Is.EqualTo(24));
            Assert.That(detail.FinalHipScore, Is.EqualTo(31));
            Assert.That(detail.ConfidenceLevel, Is.EqualTo("Medium"));
            Assert.That(detail.Reasons, Does.Contain("Browser saw phishing and executable download signals."));
            Assert.That(detail.Warnings, Does.Contain("Do not enter credentials on this page."));
            Assert.That(detail.MatchedRules.Single().RuleId, Is.EqualTo("test-phishing-rule"));
            Assert.That(detail.ProviderEvidence.Single().ProviderName, Is.EqualTo("BrowserObservedSignalProvider"));
            Assert.That(detail.FeedbackEvidence!.LooksSuspiciousWeightedTotal, Is.GreaterThan(0));
            Assert.That(detail.ReviewStatus!.Status, Is.EqualTo("Open"));
        });
    }

    /// <summary>
    /// Verifies raw URLs and private content markers are not exposed by the detail response.
    /// </summary>
    [Test]
    public async Task Detail_service_does_not_expose_raw_private_fields()
    {
        var scan = StoredScan();
        var scanRepository = new InMemoryBrowserScanResultRepository();
        await scanRepository.SaveAsync(scan, CancellationToken.None);
        var service = new AdminScanDetailService(
            scanRepository,
            new StubScanner(),
            new WeightedFeedbackAggregationService(new InMemoryWeightedFeedbackRepository()),
            new InMemoryAdminReviewQueueRepository());

        var detail = await service.GetAsync(scan.ScanResultId, CancellationToken.None);
        var json = JsonSerializer.Serialize(detail);

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Not.Contain("token=secret"));
            Assert.That(json, Does.Not.Contain("pageText"));
            Assert.That(json, Does.Not.Contain("formContents"));
            Assert.That(json, Does.Not.Contain("password"));
            Assert.That(json, Does.Contain(scan.PageUrlHash));
        });
    }

    /// <summary>
    /// Verifies unknown scan IDs return null from the application service.
    /// </summary>
    [Test]
    public async Task Detail_service_returns_null_for_unknown_scan()
    {
        var service = new AdminScanDetailService(
            new InMemoryBrowserScanResultRepository(),
            new StubScanner(),
            new WeightedFeedbackAggregationService(new InMemoryWeightedFeedbackRepository()),
            new InMemoryAdminReviewQueueRepository());

        var detail = await service.GetAsync("missing-scan", CancellationToken.None);

        Assert.That(detail, Is.Null);
    }

    /// <summary>
    /// Verifies the protected v1 admin scan details route returns layered score fields for authenticated admins.
    /// </summary>
    [Test]
    public async Task Admin_scan_details_api_returns_score_breakdown()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var scan = await SeedScanAsync(factory);
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync($"/api/v1/admin/scans/{Uri.EscapeDataString(scan.ScanResultId)}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo(scan.Domain));
            Assert.That(json.RootElement.GetProperty("urlHash").GetString(), Is.EqualTo(scan.PageUrlHash));
            Assert.That(json.RootElement.GetProperty("domainTrustScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("pageTrustScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("contentRiskScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("finalHipScore").GetInt32(), Is.InRange(0, 100));
            Assert.That(json.RootElement.GetProperty("confidenceLevel").GetString(), Is.Not.Empty);
        });
    }

    /// <summary>
    /// Verifies the protected admin route returns a safe not-found result for unknown scan IDs.
    /// </summary>
    [Test]
    public async Task Admin_scan_details_api_returns_not_found_for_unknown_scan()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/api/v1/admin/scans/missing-scan");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }

    /// <summary>
    /// Verifies the Blazor details page route renders the scan details shell for authenticated admins.
    /// </summary>
    [Test]
    public async Task Admin_scan_details_page_loads()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var scan = await SeedScanAsync(factory);
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync($"/admin/scans/{Uri.EscapeDataString(scan.ScanResultId)}");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("Scan Result Details"));
            Assert.That(html, Does.Contain("Domain Trust"));
            Assert.That(html, Does.Contain("Matched Rules"));
            Assert.That(html, Does.Not.Contain("token=secret"));
        });
    }

    /// <summary>
    /// Saves a stored browser scan directly through the configured repository so tests can address it by ID.
    /// </summary>
    /// <param name="factory">Web application factory.</param>
    /// <returns>Stored scan record.</returns>
    private static async Task<BrowserScanResultRecord> SeedScanAsync(WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBrowserScanResultRepository>();
        var scan = StoredScan();
        await repository.SaveAsync(scan, CancellationToken.None);
        return scan;
    }

    /// <summary>
    /// Creates a stored browser scan with only privacy-safe fields and a URL hash.
    /// </summary>
    /// <returns>Stored browser scan record.</returns>
    private static BrowserScanResultRecord StoredScan() =>
        new(
            $"browser-scan:test-{Guid.NewGuid():N}",
            $"scan-detail-{Guid.NewGuid():N}.com",
            "urlhash-safe-value",
            null,
            "BrowserPlugin",
            38,
            "Suspicious",
            "Suspicious",
            ["Browser saw phishing and executable download signals."],
            24,
            4,
            3,
            1,
            DateTimeOffset.UtcNow,
            "RouteToSafetyPage",
            new Dictionary<string, string>
            {
                ["downloadCandidates"] = "1",
                ["loginForms"] = "1",
                ["scanMode"] = "Normal"
            });

    /// <summary>
    /// Creates a related review queue item without private evidence.
    /// </summary>
    /// <param name="scan">Stored scan.</param>
    /// <returns>Review queue item.</returns>
    private static AdminReviewQueueItem Review(BrowserScanResultRecord scan) =>
        new(
            $"review-{Guid.NewGuid():N}",
            scan.Domain,
            scan.PageUrlHash,
            AdminReviewTargetType.Scan,
            "ScanDetailReview",
            AdminReviewSeverity.High,
            AdminReviewStatus.Open,
            AdminReviewSource.SiteSafetyScan,
            scan.ScanResultId,
            null,
            null,
            scan.Score,
            scan.Status,
            "Medium",
            "Scan requires review from privacy-safe evidence.",
            "Matched phishing and executable download labels.",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null,
            null,
            null,
            null,
            null);

    /// <summary>
    /// Adds the dev header role used by the test auth handler.
    /// </summary>
    /// <param name="client">HTTP client.</param>
    /// <param name="role">Admin role.</param>
    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-scan-admin");
    }

    /// <summary>
    /// Deterministic scanner used by service tests so detail mapping can be tested without external providers.
    /// </summary>
    private sealed class StubScanner : ISiteSafetyScanner
    {
        /// <inheritdoc />
        public Task<SiteSafetyScanResult> ScanAsync(SiteSafetyScanRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var evidence = new SiteSafetyEvidence(
                "BrowserObservedSignalProvider",
                SiteSafetyEvidenceProviderType.BrowserObserved,
                SiteSafetyEvidenceTargetType.Url,
                "scan-detail.example",
                "urlhash-safe-value",
                [new SiteSafetyEvidenceItem("KnownPhishingPattern", "true", SiteSafetyEvidenceStatus.Dangerous, 90, 0, "A privacy-safe phishing pattern matched.", EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong)],
                80,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddMinutes(5),
                [],
                true,
                false);
            var rule = new SiteSafetyRuleResult(
                "test-phishing-rule",
                "Test phishing rule",
                "Flags phishing test evidence.",
                SiteSafetyRuleSource.BuiltIn,
                SiteSafetyRuleCollectionType.PhishingRiskRules,
                SiteSafetyRiskCategory.Phishing,
                90,
                0,
                "HIP found a known phishing pattern.",
                "Do not enter credentials on this page.",
                SiteSafetyRuleSeverity.Critical,
                SiteSafetyEvidenceQuality.Confirmed,
                SiteSafetyScanStatus.Dangerous,
                0,
                true,
                false);

            return Task.FromResult(new SiteSafetyScanResult(
                "site-safety-test",
                "https://scan-detail.example/",
                "scan-detail.example",
                DateTimeOffset.UtcNow,
                0,
                90,
                0,
                0,
                70,
                45,
                25,
                80,
                SiteSafetyScanStatus.Dangerous,
                "HIP found risk signals that require review.",
                ["HIP found a known phishing pattern."],
                ["Do not enter credentials on this page."],
                [],
                ["HIP found a known phishing pattern."],
                "Medium",
                58,
                34,
                24,
                31,
                [evidence],
                new SiteSafetyScoreImpact(58, 34, 24, 31, []),
                [rule]));
        }
    }
}
