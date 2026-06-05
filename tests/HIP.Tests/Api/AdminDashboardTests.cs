using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using HIP.Application.Dashboard;
using HIP.Application.Reputation;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.SiteSafety;
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
    public async Task Dashboard_status_cards_count_real_scan_results()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var now = DateTimeOffset.UtcNow;
        await repository.SaveAsync(Scan("trusted.example", 90, "Trusted", 1, 0, 0, now, "Trusted scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("limited.example", 56, "LimitedTrustData", 1, 0, 0, now, "Limited trust data."), CancellationToken.None);
        await repository.SaveAsync(Scan("suspicious.example", 34, "Suspicious", 1, 1, 0, now, "Suspicious scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("high.example", 18, "HighRisk", 1, 1, 0, now, "High-risk scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("danger.example", 5, "Dangerous", 1, 1, 1, now, "Dangerous scan."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "trustedResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "limitedTrustResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "suspiciousResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "highRiskResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "dangerousResults").Value, Is.EqualTo(1));
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
    public async Task Dashboard_review_cards_include_generated_review_signals()
    {
        var generatedReviews = new InMemoryAdminReviewQueueRepository();
        await generatedReviews.SaveAsync(AdminReview("review-high", AdminReviewSeverity.High, DateTimeOffset.UtcNow.AddHours(-3)), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), generatedReviewRepository: generatedReviews);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "pendingReviewItems").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "highSeverityReviewItems").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "oldestOpenReviewAgeHours").Value, Is.GreaterThanOrEqualTo(3));
        });
    }

    [Test]
    public async Task Dashboard_feedback_cards_count_weighted_feedback()
    {
        var feedback = new InMemoryWeightedFeedbackRepository();
        var now = DateTimeOffset.UtcNow;
        await feedback.SaveAsync(Feedback("feedback.example", HipFeedbackType.LooksSafe, now), CancellationToken.None);
        await feedback.SaveAsync(Feedback("feedback.example", HipFeedbackType.LooksSuspicious, now), CancellationToken.None);
        await feedback.SaveAsync(Feedback("feedback.example", HipFeedbackType.ReportIssue, now), CancellationToken.None);
        await feedback.SaveAsync(Feedback("spike.example", HipFeedbackType.LooksSuspicious, now, "reporter-1"), CancellationToken.None);
        await feedback.SaveAsync(Feedback("spike.example", HipFeedbackType.LooksSuspicious, now, "reporter-2"), CancellationToken.None);
        await feedback.SaveAsync(Feedback("spike.example", HipFeedbackType.LooksSuspicious, now, "reporter-3"), CancellationToken.None);
        await feedback.SaveAsync(Feedback("spike.example", HipFeedbackType.ReportIssue, now, "reporter-4"), CancellationToken.None);
        await feedback.SaveAsync(Feedback("spike.example", HipFeedbackType.ReportIssue, now, "reporter-5"), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), weightedFeedbackRepository: feedback);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "feedbackReceived").Value, Is.EqualTo(8));
            Assert.That(Card(summary, "looksSafeFeedback").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "looksSuspiciousFeedback").Value, Is.EqualTo(4));
            Assert.That(Card(summary, "reportIssueFeedback").Value, Is.EqualTo(3));
            Assert.That(Card(summary, "suspiciousFeedbackSpikes").Value, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Dashboard_rule_cards_include_built_in_admin_and_disabled_rules()
    {
        var trustRules = new InMemoryRuleRepository();
        await trustRules.SaveAsync(TrustRule("trust-watch", RuleMode.Watch, enabled: true), CancellationToken.None);
        await trustRules.SaveAsync(TrustRule("trust-disabled", RuleMode.Disabled, enabled: false), CancellationToken.None);
        var adminRules = new InMemoryAdminSiteSafetyRuleRepository();
        await adminRules.SaveAsync(AdminRule("admin-active", AdminSiteSafetyRuleStatus.Active, AdminSiteSafetyRuleMode.Enforced), CancellationToken.None);
        await adminRules.SaveAsync(AdminRule("admin-watch", AdminSiteSafetyRuleStatus.Active, AdminSiteSafetyRuleMode.WatchOnly), CancellationToken.None);
        await adminRules.SaveAsync(AdminRule("admin-simulation", AdminSiteSafetyRuleStatus.Draft, AdminSiteSafetyRuleMode.Simulation), CancellationToken.None);
        await adminRules.SaveAsync(AdminRule("admin-disabled", AdminSiteSafetyRuleStatus.Disabled, AdminSiteSafetyRuleMode.Simulation), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), ruleRepository: trustRules, adminSiteSafetyRuleRepository: adminRules);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "activeBuiltInRules").Value, Is.GreaterThan(0));
            Assert.That(Card(summary, "activeAdminRules").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "watchOnlyRules").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "simulationRules").Value, Is.EqualTo(2));
            Assert.That(Card(summary, "disabledRules").Value, Is.EqualTo(2));
        });
    }

    [Test]
    public async Task Dashboard_marks_missing_feedback_and_external_provider_data_as_placeholders()
    {
        var service = Dashboard(new InMemoryBrowserScanResultRepository());

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "feedbackReceived").IsPlaceholder, Is.True);
            Assert.That(Card(summary, "externalProviderErrors").IsPlaceholder, Is.True);
            Assert.That(Card(summary, "externalProviderErrors").Status, Is.EqualTo("Not connected yet"));
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
    private static AdminDashboardService Dashboard(
        IBrowserScanResultRepository browserScanRepository,
        IAdminReviewQueueRepository? generatedReviewRepository = null,
        IWeightedFeedbackRepository? weightedFeedbackRepository = null,
        IAdminSiteSafetyRuleRepository? adminSiteSafetyRuleRepository = null,
        IRuleRepository? ruleRepository = null)
    {
        var auditLogService = new AuditLogService();
        return new AdminDashboardService(
            browserScanRepository,
            new InMemoryRiskFindingReportRepository(),
            new ReviewQueueService(new ReviewItemValidator(), auditLogService),
            new AppealService(new AppealRequestValidator(), auditLogService),
            new ReputationOverrideService(new ReputationOverrideRequestValidator(), auditLogService),
            auditLogService,
            ruleRepository ?? new InMemoryRuleRepository(),
            new InMemoryGeneratedRuleCandidateRepository(),
            generatedReviewRepository ?? new InMemoryAdminReviewQueueRepository(),
            weightedFeedbackRepository ?? new InMemoryWeightedFeedbackRepository(),
            adminSiteSafetyRuleRepository ?? new InMemoryAdminSiteSafetyRuleRepository());
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

    /// <summary>
    /// Creates a generated admin review queue item with privacy-safe summary fields.
    /// </summary>
    /// <param name="reviewId">Review ID.</param>
    /// <param name="severity">Review severity.</param>
    /// <param name="createdAtUtc">Creation time.</param>
    /// <returns>Admin review queue item.</returns>
    private static AdminReviewQueueItem AdminReview(string reviewId, AdminReviewSeverity severity, DateTimeOffset createdAtUtc) =>
        new(
            reviewId,
            "review.example",
            "sha256:review",
            AdminReviewTargetType.Domain,
            "DashboardTest",
            severity,
            AdminReviewStatus.Open,
            AdminReviewSource.SiteSafetyScan,
            null,
            null,
            null,
            42,
            "HighRisk",
            "Medium",
            "Privacy-safe review summary.",
            "Privacy-safe evidence summary.",
            createdAtUtc,
            createdAtUtc,
            null,
            null,
            null,
            null,
            null);

    /// <summary>
    /// Creates privacy-safe weighted feedback for dashboard aggregation.
    /// </summary>
    /// <param name="domain">Feedback domain.</param>
    /// <param name="feedbackType">Feedback type.</param>
    /// <param name="submittedAtUtc">Submission time.</param>
    /// <param name="reporterHash">Optional reporter hash used only for abuse controls.</param>
    /// <returns>Weighted feedback submission.</returns>
    private static WeightedFeedbackSubmission Feedback(
        string domain,
        HipFeedbackType feedbackType,
        DateTimeOffset submittedAtUtc,
        string? reporterHash = null) =>
        new(
            domain,
            feedbackType,
            HipFeedbackSource.BrowserPluginBanner,
            HIP.Domain.Reputation.ReporterTrustLevel.Anonymous,
            submittedAtUtc,
            PageUrlHash: "sha256:page",
            ReporterHash: reporterHash,
            PluginVersion: "0.1.0-test");

    /// <summary>
    /// Creates a minimal JSON trust rule for dashboard rule count tests.
    /// </summary>
    /// <param name="ruleId">Rule ID.</param>
    /// <param name="mode">Rule mode.</param>
    /// <param name="enabled">Whether the rule is enabled.</param>
    /// <returns>Trust rule.</returns>
    private static TrustRule TrustRule(string ruleId, RuleMode mode, bool enabled) =>
        new(
            ruleId,
            ruleId,
            string.Empty,
            enabled,
            mode,
            RuleSeverity.Low,
            [],
            [],
            false,
            false,
            "test",
            "Dashboard test rule.",
            ApprovalStatus.NotRequired,
            0,
            1);

    /// <summary>
    /// Creates a minimal admin Site Safety rule for dashboard rule-state counts.
    /// </summary>
    /// <param name="ruleId">Rule ID.</param>
    /// <param name="status">Rule lifecycle status.</param>
    /// <param name="mode">Rule execution mode.</param>
    /// <returns>Admin Site Safety rule.</returns>
    private static AdminSiteSafetyRule AdminRule(string ruleId, AdminSiteSafetyRuleStatus status, AdminSiteSafetyRuleMode mode) =>
        new(
            ruleId,
            ruleId,
            "Dashboard rule count test.",
            AdminSiteSafetyRuleTargetType.Domain,
            [],
            new AdminSiteSafetyRuleEffects(AddReason: "Dashboard test rule."),
            SiteSafetyRuleSeverity.Low,
            SiteSafetyEvidenceQuality.Weak,
            status,
            mode,
            "test",
            DateTimeOffset.UtcNow,
            status is AdminSiteSafetyRuleStatus.Active or AdminSiteSafetyRuleStatus.Approved ? "approver" : null,
            status is AdminSiteSafetyRuleStatus.Active or AdminSiteSafetyRuleStatus.Approved ? DateTimeOffset.UtcNow : null,
            1,
            null,
            false);
}
