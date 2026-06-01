using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Application.Dashboard;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminDashboardTests
{
    [Test]
    public async Task Dashboard_summary_returns_counts()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Owner");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var summary = await response.Content.ReadFromJsonAsync<AdminDashboardSummary>();
        Assert.That(summary, Is.Not.Null);
        Assert.That(summary!.Cards.Select(card => card.Key), Does.Contain("totalScans"));
        Assert.That(summary.Cards.Select(card => card.Key), Does.Contain("linksScanned"));
        Assert.That(summary.Cards.Select(card => card.Key), Does.Contain("apiHealth"));
    }

    [Test]
    public async Task Dashboard_summary_uses_stored_scan_results()
    {
        var service = await DashboardWithScansAsync();

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary.HasScanData, Is.True);
            Assert.That(summary.DataSource, Is.EqualTo("BrowserPluginScanResults"));
            Assert.That(Card(summary, "totalScans").Value, Is.EqualTo(3));
        });
    }

    [Test]
    public async Task Dashboard_scan_card_totals_are_correct()
    {
        var service = await DashboardWithScansAsync();

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "domainsScanned").Value, Is.EqualTo(3));
            Assert.That(Card(summary, "linksScanned").Value, Is.EqualTo(45));
            Assert.That(Card(summary, "riskyLinksFound").Value, Is.EqualTo(7));
            Assert.That(Card(summary, "dangerousLinksFound").Value, Is.EqualTo(3));
            Assert.That(Card(summary, "averageHipScore").Value, Is.EqualTo(66));
        });
    }

    [Test]
    public async Task Dashboard_scans_last_24_hours_is_calculated_correctly()
    {
        var service = await DashboardWithScansAsync();

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "scansLast24Hours").Value, Is.EqualTo(2));
            Assert.That(Card(summary, "scansLast7Days").Value, Is.EqualTo(3));
        });
    }

    [Test]
    public async Task Dashboard_no_data_state_works_when_no_scans_exist()
    {
        var service = Dashboard(new InMemoryBrowserScanResultRepository());

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary.HasScanData, Is.False);
            Assert.That(summary.DataSource, Is.EqualTo("NoStoredScanData"));
            Assert.That(Card(summary, "totalScans").IsPlaceholder, Is.True);
            Assert.That(Card(summary, "totalScans").Value, Is.EqualTo(0));
        });
    }

    [Test]
    public async Task Dashboard_top_risky_domains_are_sorted_by_risk()
    {
        var service = await DashboardWithScansAsync();

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.TopRiskyDomains.First().Domain, Is.EqualTo("danger.example"));
        Assert.That(summary.TopRiskyDomains.First().DangerousLinksFound, Is.EqualTo(3));
    }

    [Test]
    public async Task Dashboard_recent_scans_are_sorted_newest_first()
    {
        var service = await DashboardWithScansAsync();

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentScans.Select(scan => scan.Domain).First(), Is.EqualTo("caution.example"));
    }

    [Test]
    public async Task Dashboard_scan_sections_do_not_expose_private_page_text_or_form_values()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("privacy.example", 70, "ProbablySafe", 1, 1, 0, DateTimeOffset.UtcNow, "Safe summary."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var serialized = JsonSerializer.Serialize(summary);

        Assert.Multiple(() =>
        {
            Assert.That(serialized, Does.Not.Contain("pageText"));
            Assert.That(serialized, Does.Not.Contain("formValues"));
            Assert.That(serialized, Does.Not.Contain("password"));
            Assert.That(serialized, Does.Not.Contain("token"));
        });
    }

    [Test]
    public async Task Dashboard_summary_does_not_expose_private_content()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var privateToken = "private-token-should-not-appear";
        var senderHash = "sender-hash-should-not-appear";
        var report = new RiskFindingReport(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "risky.example",
            "hash-1",
            $"https://risky.example/{privateToken}",
            senderHash,
            RiskStatus.HighRisk,
            "Suspicious redirect summary.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence(
                "test",
                "Privacy-safe summary only.",
                new Dictionary<string, string> { ["privateEvidence"] = "must-not-render" }),
            "hip-signature-placeholder");

        var ingest = await client.PostAsJsonAsync("/api/v1/public/risk-findings", report);
        Assert.That(ingest.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        AddRole(client, "Owner");
        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(body, Does.Not.Contain(privateToken));
        Assert.That(body, Does.Not.Contain(senderHash));
        Assert.That(body, Does.Not.Contain("must-not-render"));
        Assert.That(body, Does.Contain("Suspicious redirect summary."));
    }

    [Test]
    public async Task Unauthorized_users_cannot_access_admin_dashboard_api()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Readonly_can_view_summary()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Dashboard_route_exists()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Dashboard_risky_domains_api_is_protected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/risky-domains");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Dashboard_recent_scans_api_is_protected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/recent-scans");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Recent_activity_uses_privacy_safe_summaries()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/v1/public/risk-findings", new RiskFindingReport(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "privacy-safe.example",
            "hash-2",
            "https://privacy-safe.example/secret-path",
            "sender-secret",
            RiskStatus.Dangerous,
            "Known dangerous domain signal.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Evidence summary.", new Dictionary<string, string>()),
            "hip-signature-placeholder"));

        AddRole(client, "Owner");
        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");
        var summary = await response.Content.ReadFromJsonAsync<AdminDashboardSummary>();

        Assert.That(summary!.RecentActivity, Is.Not.Empty);
        var serialized = JsonSerializer.Serialize(summary.RecentActivity);
        Assert.That(serialized, Does.Contain("Known dangerous domain signal."));
        Assert.That(serialized, Does.Not.Contain("secret-path"));
        Assert.That(serialized, Does.Not.Contain("sender-secret"));
    }

    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-Role");
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-User");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-dashboard-test");
    }

    /// <summary>
    /// Finds a card by key in a dashboard summary.
    /// </summary>
    /// <param name="summary">Dashboard summary.</param>
    /// <param name="key">Card key.</param>
    /// <returns>Matching card.</returns>
    private static AdminDashboardCard Card(AdminDashboardSummary summary, string key) =>
        summary.Cards.Single(card => card.Key == key);

    /// <summary>
    /// Creates a dashboard service seeded with representative browser scan data.
    /// </summary>
    /// <returns>Dashboard service.</returns>
    private static async Task<AdminDashboardService> DashboardWithScansAsync()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var now = DateTimeOffset.UtcNow;
        await repository.SaveAsync(Scan("safe.example", 84, "Trusted", 10, 0, 0, now.AddHours(-1), "No risky links found."), CancellationToken.None);
        await repository.SaveAsync(Scan("danger.example", 38, "HighRisk", 20, 5, 3, now.AddDays(-2), "Dangerous links found."), CancellationToken.None);
        await repository.SaveAsync(Scan("caution.example", 75, "ProbablySafe", 15, 2, 0, now.AddMinutes(-10), "Some caution links found."), CancellationToken.None);
        return Dashboard(repository);
    }

    /// <summary>
    /// Creates a dashboard service with isolated in-memory dependencies.
    /// </summary>
    /// <param name="browserScanRepository">Browser scan repository.</param>
    /// <returns>Dashboard service.</returns>
    private static AdminDashboardService Dashboard(IBrowserScanResultRepository browserScanRepository)
    {
        var auditLogService = new AuditLogService();
        return new AdminDashboardService(
            browserScanRepository,
            new InMemoryRiskFindingReportRepository(),
            new ReviewQueueService(new ReviewItemValidator(), auditLogService),
            new AppealService(new AppealRequestValidator(), auditLogService),
            new ReputationOverrideService(new ReputationOverrideRequestValidator(), auditLogService),
            auditLogService,
            new InMemoryRuleRepository(),
            new InMemoryGeneratedRuleCandidateRepository());
    }

    /// <summary>
    /// Creates a privacy-safe stored browser scan record for dashboard aggregation tests.
    /// </summary>
    /// <param name="domain">Scanned domain.</param>
    /// <param name="score">HIP score.</param>
    /// <param name="riskLevel">Risk level text.</param>
    /// <param name="linksScanned">Links scanned.</param>
    /// <param name="riskyLinks">Risky links found.</param>
    /// <param name="dangerousLinks">Dangerous links found.</param>
    /// <param name="lastCheckedUtc">Scan timestamp.</param>
    /// <param name="reason">Public-safe reason.</param>
    /// <returns>Browser scan result record.</returns>
    private static BrowserScanResultRecord Scan(
        string domain,
        int score,
        string riskLevel,
        int linksScanned,
        int riskyLinks,
        int dangerousLinks,
        DateTimeOffset lastCheckedUtc,
        string reason) =>
        new(
            $"scan-{Guid.NewGuid():N}",
            domain,
            "sha256:test",
            null,
            "BrowserPlugin",
            score,
            riskLevel,
            riskLevel,
            [reason],
            linksScanned,
            riskyLinks,
            Math.Max(0, riskyLinks - dangerousLinks),
            dangerousLinks,
            lastCheckedUtc,
            dangerousLinks > 0 ? "RouteToSafetyPage" : "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal"
            });
}
