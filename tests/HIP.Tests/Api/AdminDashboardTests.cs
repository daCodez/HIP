using System.Net;
using System.Net.Http.Json;
using System.Reflection;
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
using HIP.Application.Scalability;
using HIP.Application.SelfHealing;
using HIP.Application.SiteSafety;
using HIP.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminDashboardTests
{
    [Test]
    public async Task Dashboard_summary_returns_counts()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
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
        await repository.SaveAsync(Scan("mostly.example", 76, "MostlyTrusted", 1, 0, 0, now, "Mostly trusted scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("limited.example", 56, "LimitedTrustData", 1, 0, 0, now, "Limited trust data."), CancellationToken.None);
        await repository.SaveAsync(Scan("unknown.example", 45, "Unknown", 1, 0, 0, now, "Unknown scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("suspicious.example", 34, "Suspicious", 1, 1, 0, now, "Suspicious scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("high.example", 18, "HighRisk", 1, 1, 0, now, "High-risk scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("danger.example", 5, "Dangerous", 1, 1, 1, now, "Dangerous scan."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Card(summary, "trustedResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "mostlyTrustedResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "limitedTrustResults").Value, Is.EqualTo(1));
            Assert.That(Card(summary, "unknownResults").Value, Is.EqualTo(1));
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
    public async Task Dashboard_external_provider_errors_use_stored_scan_metadata()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan(
            "provider-error.example",
            52,
            "LimitedTrustData",
            4,
            0,
            0,
            DateTimeOffset.UtcNow,
            "Provider evidence was collected safely.",
            new Dictionary<string, string>
            {
                ["externalProviderErrors"] = "2",
                ["sslLabsStatus"] = "Timeout"
            }), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var card = Card(summary, "externalProviderErrors");

        Assert.Multiple(() =>
        {
            Assert.That(card.Value, Is.EqualTo(2));
            Assert.That(card.Status, Is.EqualTo("Errors"));
            Assert.That(card.IsPlaceholder, Is.False);
        });
    }

    [Test]
    public async Task Dashboard_external_provider_errors_use_generated_review_signals()
    {
        var generatedReviews = new InMemoryAdminReviewQueueRepository();
        await generatedReviews.SaveAsync(AdminReview(
            "provider-timeout",
            "provider-timeout.example",
            "ImportantProviderFailure",
            AdminReviewSeverity.Medium,
            AdminReviewSource.ExternalProvider,
            DateTimeOffset.UtcNow,
            "LimitedTrustData",
            "External provider timeout was recorded safely."), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), generatedReviewRepository: generatedReviews);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var card = Card(summary, "externalProviderErrors");

        Assert.Multiple(() =>
        {
            Assert.That(card.Value, Is.EqualTo(1));
            Assert.That(card.Status, Is.EqualTo("Errors"));
            Assert.That(card.IsPlaceholder, Is.False);
        });
    }

    [Test]
    public async Task Dashboard_external_provider_card_shows_connected_when_provider_data_has_no_errors()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan(
            "provider-clean.example",
            60,
            "LimitedTrustData",
            4,
            0,
            0,
            DateTimeOffset.UtcNow,
            "Provider evidence was collected safely.",
            new Dictionary<string, string>
            {
                ["sslLabsStatus"] = "Clean",
                ["providerErrorCount"] = "0"
            }), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var card = Card(summary, "externalProviderErrors");

        Assert.Multiple(() =>
        {
            Assert.That(card.Value, Is.EqualTo(0));
            Assert.That(card.Status, Is.EqualTo("Connected"));
            Assert.That(card.IsPlaceholder, Is.False);
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
    public async Task Dashboard_empty_state_does_not_generate_fake_activity_or_threats()
    {
        var service = Dashboard(new InMemoryBrowserScanResultRepository());

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary.RecentThreats, Is.Empty);
            Assert.That(summary.TopRiskyDomains, Is.Empty);
            Assert.That(summary.RecentScans, Is.Empty);
            Assert.That(Card(summary, "totalScans").Status, Is.EqualTo("No Data"));
            Assert.That(Card(summary, "feedbackReceived").Status, Is.EqualTo("No Data"));
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

    /// <summary>
    /// Verifies recent scan rows include the layered score and provenance fields needed by the admin table.
    /// </summary>
    [Test]
    public async Task Dashboard_recent_scan_rows_include_layered_scores_confidence_and_plugin_version()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan(
            "layered.example",
            44,
            "Suspicious",
            12,
            3,
            1,
            DateTimeOffset.UtcNow,
            "Executable download and redirect signals were observed.",
            new Dictionary<string, string>
            {
                ["domainTrustScore"] = "91",
                ["pageTrustScore"] = "37",
                ["contentRiskScore"] = "22",
                ["confidence"] = "Medium",
                ["source"] = "SiteSafetyScan",
                ["pluginVersion"] = "HIP Plugin v0.1.0-dev"
            }), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var row = summary.RecentScans.Single();

        Assert.Multiple(() =>
        {
            Assert.That(row.Domain, Is.EqualTo("layered.example"));
            Assert.That(row.Status, Is.EqualTo("Suspicious"));
            Assert.That(row.Score, Is.EqualTo(44));
            Assert.That(row.DomainTrustScore, Is.EqualTo(91));
            Assert.That(row.PageTrustScore, Is.EqualTo(37));
            Assert.That(row.ContentRiskScore, Is.EqualTo(22));
            Assert.That(row.ConfidenceLevel, Is.EqualTo("Medium"));
            Assert.That(row.Source, Is.EqualTo("SiteSafetyScan"));
            Assert.That(row.PluginVersion, Is.EqualTo("HIP Plugin v0.1.0-dev"));
            Assert.That(row.ReasonSummary, Does.Contain("Executable download"));
        });
    }

    /// <summary>
    /// Verifies recent scan rows fall back safely when older stored scans do not have layered metadata.
    /// </summary>
    [Test]
    public async Task Dashboard_recent_scan_rows_use_safe_unknowns_when_metadata_is_missing()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("old.example", 56, "LimitedTrustData", 3, 0, 0, DateTimeOffset.UtcNow, "Older scan."), CancellationToken.None);
        var service = Dashboard(repository);

        var row = (await service.GetSummaryAsync(CancellationToken.None)).RecentScans.Single();

        Assert.Multiple(() =>
        {
            Assert.That(row.DomainTrustScore, Is.Null);
            Assert.That(row.PageTrustScore, Is.Null);
            Assert.That(row.ContentRiskScore, Is.Null);
            Assert.That(row.ConfidenceLevel, Is.EqualTo("Unknown"));
            Assert.That(row.Source, Is.EqualTo("BrowserPlugin"));
            Assert.That(row.PluginVersion, Is.EqualTo("Unknown"));
        });
    }

    /// <summary>
    /// Verifies recent scan rows remain privacy-safe and do not surface raw URL or private-content markers.
    /// </summary>
    [Test]
    public async Task Dashboard_recent_scan_rows_do_not_expose_private_fields()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan(
            "privacy.example",
            40,
            "Suspicious",
            8,
            2,
            0,
            DateTimeOffset.UtcNow,
            "Suspicious link signals were observed.",
            new Dictionary<string, string>
            {
                ["pluginVersion"] = "HIP Plugin v0.1.0-dev",
                ["source"] = "BrowserPlugin",
                ["confidence"] = "High"
            }), CancellationToken.None);
        var service = Dashboard(repository);

        var json = JsonSerializer.Serialize((await service.GetSummaryAsync(CancellationToken.None)).RecentScans);

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Not.Contain("pageUrl"));
            Assert.That(json, Does.Not.Contain("password"));
            Assert.That(json, Does.Not.Contain("token"));
            Assert.That(json, Does.Not.Contain("cookie"));
            Assert.That(json, Does.Not.Contain("formValues"));
            Assert.That(json, Does.Not.Contain("private messages"));
        });
    }

    /// <summary>
    /// Verifies the admin dashboard markup contains the recent scan table columns and empty-state copy.
    /// </summary>
    [Test]
    public async Task Dashboard_route_contains_recent_scan_table_columns_and_empty_state()
    {
        var source = ReadDashboardSource();

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("Recent Scans"));
            Assert.That(source, Does.Contain("Final Score"));
            Assert.That(source, Does.Contain("Domain Trust"));
            Assert.That(source, Does.Contain("Page Trust"));
            Assert.That(source, Does.Contain("Content Risk"));
            Assert.That(source, Does.Contain("Confidence"));
            Assert.That(source, Does.Contain("No scans yet."));
            Assert.That(source, Does.Contain("Scan history not connected yet").Or.Contain("Run the browser plugin"));
        });
    }

    [Test]
    public async Task Recent_threats_do_not_show_clean_pages()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var now = DateTimeOffset.UtcNow;
        await repository.SaveAsync(Scan("trusted.example", 92, "Trusted", 12, 0, 0, now, "No risky links found."), CancellationToken.None);
        await repository.SaveAsync(Scan("limited.example", 58, "LimitedTrustData", 7, 0, 0, now, "No obvious malware or phishing found."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentThreats, Is.Empty);
    }

    [Test]
    public async Task Dangerous_scan_appears_in_recent_threats()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("danger.example", 4, "Dangerous", 12, 4, 2, DateTimeOffset.UtcNow, "Confirmed malware indicator."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        var threat = summary.RecentThreats.Single();
        Assert.Multiple(() =>
        {
            Assert.That(threat.Domain, Is.EqualTo("danger.example"));
            Assert.That(threat.Severity, Is.EqualTo("Critical"));
            Assert.That(threat.Source, Is.EqualTo("BrowserPlugin"));
        });
    }

    [Test]
    public async Task Highrisk_scan_appears_in_recent_threats()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("high.example", 18, "HighRisk", 8, 3, 0, DateTimeOffset.UtcNow, "Suspicious redirect chain found."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentThreats.Single().Domain, Is.EqualTo("high.example"));
    }

    [Test]
    public async Task Suspicious_scan_with_warning_appears_in_recent_threats()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("suspicious.example", 32, "Suspicious", 9, 1, 0, DateTimeOffset.UtcNow, "Warning: suspicious download link found."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentThreats.Single().ReasonSummary, Does.Contain("suspicious link signals"));
    }

    [Test]
    public async Task Unknown_login_page_review_signal_appears_in_recent_threats()
    {
        var generatedReviews = new InMemoryAdminReviewQueueRepository();
        await generatedReviews.SaveAsync(AdminReview(
            "unknown-login",
            "login.example",
            "UnknownDomainLoginForm",
            AdminReviewSeverity.Medium,
            AdminReviewSource.SiteSafetyScan,
            DateTimeOffset.UtcNow,
            "LimitedTrustData",
            "Unknown login page needs review."), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), generatedReviewRepository: generatedReviews);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentThreats.Single().ReasonSummary, Is.EqualTo("Unknown login page needs review."));
    }

    [Test]
    public async Task Repeated_suspicious_feedback_appears_in_recent_threats()
    {
        var feedback = new InMemoryWeightedFeedbackRepository();
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 5; i++)
        {
            await feedback.SaveAsync(Feedback("feedback-threat.example", HipFeedbackType.LooksSuspicious, now.AddMinutes(i), $"reporter-{i}"), CancellationToken.None);
        }

        var service = Dashboard(new InMemoryBrowserScanResultRepository(), weightedFeedbackRepository: feedback);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        var threat = summary.RecentThreats.Single();
        Assert.Multiple(() =>
        {
            Assert.That(threat.Domain, Is.EqualTo("feedback-threat.example"));
            Assert.That(threat.Source, Is.EqualTo(HipFeedbackSource.BrowserPluginBanner.ToString()));
            Assert.That(threat.ReasonSummary, Does.Contain("Repeated suspicious feedback"));
        });
    }

    [Test]
    public async Task External_provider_threat_hit_appears_in_recent_threats()
    {
        var generatedReviews = new InMemoryAdminReviewQueueRepository();
        await generatedReviews.SaveAsync(AdminReview(
            "provider-hit",
            "provider-hit.example",
            "ExternalProviderThreatHit",
            AdminReviewSeverity.High,
            AdminReviewSource.ExternalProvider,
            DateTimeOffset.UtcNow,
            "Dangerous",
            "External provider reported phishing evidence."), CancellationToken.None);
        var service = Dashboard(new InMemoryBrowserScanResultRepository(), generatedReviewRepository: generatedReviews);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        var threat = summary.RecentThreats.Single();
        Assert.Multiple(() =>
        {
            Assert.That(threat.Source, Is.EqualTo(AdminReviewSource.ExternalProvider.ToString()));
            Assert.That(threat.SiteSafetyStatus, Is.EqualTo("Dangerous"));
        });
    }

    [Test]
    public async Task Recent_threats_are_sorted_newest_first()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("older.example", 8, "Dangerous", 3, 2, 1, DateTimeOffset.UtcNow.AddHours(-3), "Older dangerous scan."), CancellationToken.None);
        await repository.SaveAsync(Scan("newer.example", 18, "HighRisk", 3, 1, 0, DateTimeOffset.UtcNow, "Newer high-risk scan."), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);

        Assert.That(summary.RecentThreats.First().Domain, Is.EqualTo("newer.example"));
    }

    [Test]
    public async Task Dashboard_route_starts_with_the_overview_heading()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("HIP Admin · dashboard"));
            Assert.That(body, Does.Contain("Overview"));
            Assert.That(body, Does.Contain("Monitor identity signals, investigate risk, and keep HIP healthy."));
            Assert.That(body, Does.Not.Contain("Privacy-safe operational overview"));
            Assert.That(body, Does.Not.Contain("HIP Local Launcher"));
            Assert.That(body, Does.Contain("Recent threats"));
        });
    }

    [Test]
    public void Dashboard_source_contains_visual_command_centre_sections()
    {
        var source = ReadDashboardSource();

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("<h1>Overview</h1>"));
            Assert.That(source, Does.Contain("IAdminDashboardService"));
            Assert.That(source, Does.Contain("Overall HIP protection"));
            Assert.That(source, Does.Contain("Scan activity"));
            Assert.That(source, Does.Contain("Risk breakdown"));
            Assert.That(source, Does.Contain("Provider health"));
            Assert.That(source, Does.Contain("System activity"));
        });
    }

    [Test]
    public async Task Recent_threats_do_not_expose_private_content()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        await repository.SaveAsync(Scan("privacy-threat.example", 10, "HighRisk", 4, 0, 0, DateTimeOffset.UtcNow, "password token=secret page text form value private message cookie"), CancellationToken.None);
        var service = Dashboard(repository);

        var summary = await service.GetSummaryAsync(CancellationToken.None);
        var serialized = JsonSerializer.Serialize(summary.RecentThreats);

        Assert.Multiple(() =>
        {
            Assert.That(serialized, Does.Contain("[privacy-safe threat summary redacted]"));
            Assert.That(serialized, Does.Not.Contain("password token=secret"));
            Assert.That(serialized, Does.Not.Contain("form value"));
            Assert.That(serialized, Does.Not.Contain("private message"));
        });
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
        await using var factory = new HipWebApplicationFactory<Program>();
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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Readonly_can_view_summary()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Dashboard_route_exists()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Dashboard_risky_domains_api_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/risky-domains");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Dashboard_recent_scans_api_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/recent-scans");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Recent_activity_uses_privacy_safe_summaries()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
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

    /// <summary>
    /// Verifies the dashboard version marker comes from HIP.Web assembly metadata instead of duplicated UI text.
    /// </summary>
    [Test]
    public void Dashboard_version_uses_web_assembly_informational_version()
    {
        var informationalVersion = typeof(HipWebBuildInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        Assert.Multiple(() =>
        {
            Assert.That(HipWebBuildInfo.Version, Is.EqualTo(informationalVersion));
            Assert.That(HipWebBuildInfo.DashboardDisplayVersion, Is.EqualTo($"HIP Dashboard v{informationalVersion}"));
        });
    }

    /// <summary>
    /// Verifies the admin dashboard references the shared build marker so stale hardcoded version labels are avoided.
    /// </summary>
    [Test]
    public void Dashboard_page_references_shared_build_marker()
    {
        var source = ReadDashboardSource();

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("HipWebBuildInfo.DashboardDisplayVersion"));
            Assert.That(source, Does.Not.Contain("HIP Dashboard v0.2.1-dev"));
        });
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
    /// Reads the dashboard Razor source from the repository root so markup-only refresh states are covered.
    /// </summary>
    /// <returns>Dashboard Razor source text.</returns>
    private static string ReadDashboardSource()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "HIP.Web", "Components", "Pages", "AdminDashboard.razor");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("Could not locate AdminDashboard.razor from the test output directory.");
    }

    /// <summary>
    /// Dashboard service used to verify the UI returns a safe generic refresh error without leaking exception details.
    /// </summary>
    private sealed class FailingDashboardService : IAdminDashboardService
    {
        /// <inheritdoc />
        public Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("private stack trace database-password token=secret");
    }

    /// <summary>
    /// Dashboard service used to verify the no-data UI without depending on a developer database state.
    /// </summary>
    private sealed class EmptyDashboardService : IAdminDashboardService
    {
        /// <inheritdoc />
        public Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new AdminDashboardSummary(
                [
                    new AdminDashboardCard(
                        "totalScans",
                        "Total Scans",
                        0,
                        "No Data",
                        true,
                        "No stored scan results are available yet.")
                ],
                [],
                "Healthy",
                DateTimeOffset.UtcNow,
                "NoStoredScanData",
                false,
                [],
                [],
                []));
    }

    /// <summary>
    /// Creates a dashboard service seeded with representative browser scan data.
    /// </summary>
    /// <returns>Dashboard service.</returns>
    private static async Task<AdminDashboardService> DashboardWithScansAsync()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var aggregate = new InMemoryDashboardScanAggregateStore();
        var now = DateTimeOffset.UtcNow;
        var scans = new[]
        {
            Scan("safe.example", 84, "Trusted", 10, 0, 0, now.AddHours(-1), "No risky links found."),
            Scan("danger.example", 38, "HighRisk", 20, 5, 3, now.AddDays(-2), "Dangerous links found."),
            Scan("caution.example", 75, "ProbablySafe", 15, 2, 0, now.AddMinutes(-10), "Some caution links found.")
        };

        foreach (var scan in scans)
        {
            await repository.SaveAsync(scan, CancellationToken.None);
            await aggregate.UpdateAsync(scan, CancellationToken.None);
        }

        return Dashboard(repository, dashboardScanAggregateStore: aggregate);
    }

    /// <summary>
    /// Creates a dashboard service with isolated in-memory dependencies.
    /// </summary>
    /// <param name="browserScanRepository">Browser scan repository.</param>
    /// <returns>Dashboard service.</returns>
    private static AdminDashboardService Dashboard(
        IBrowserScanResultRepository browserScanRepository,
        IDashboardScanAggregateStore? dashboardScanAggregateStore = null,
        IRiskFindingReportRepository? riskFindingRepository = null,
        IAdminReviewQueueRepository? generatedReviewRepository = null,
        IWeightedFeedbackRepository? weightedFeedbackRepository = null,
        IAdminSiteSafetyRuleRepository? adminSiteSafetyRuleRepository = null,
        IRuleRepository? ruleRepository = null)
    {
        var auditLogRepository = new InMemoryAuditLogRepository();
        return new AdminDashboardService(
            browserScanRepository,
            dashboardScanAggregateStore ?? new InMemoryDashboardScanAggregateStore(),
            riskFindingRepository ?? new InMemoryRiskFindingReportRepository(),
            new InMemoryReviewQueueRepository(),
            new InMemoryAppealRepository(),
            new InMemoryReputationOverrideRequestRepository(),
            auditLogRepository,
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
        string reason,
        IReadOnlyDictionary<string, string>? metadata = null) =>
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
            metadata ?? new Dictionary<string, string>
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
    /// Creates a generated admin review queue item with configurable threat evidence.
    /// </summary>
    /// <param name="reviewId">Review ID.</param>
    /// <param name="domain">Review domain.</param>
    /// <param name="reason">Machine-readable review reason.</param>
    /// <param name="severity">Review severity.</param>
    /// <param name="source">Review source.</param>
    /// <param name="createdAtUtc">Creation timestamp.</param>
    /// <param name="currentStatus">Current Site Safety status.</param>
    /// <param name="summary">Privacy-safe summary.</param>
    /// <returns>Admin review queue item.</returns>
    private static AdminReviewQueueItem AdminReview(
        string reviewId,
        string domain,
        string reason,
        AdminReviewSeverity severity,
        AdminReviewSource source,
        DateTimeOffset createdAtUtc,
        string currentStatus,
        string summary) =>
        new(
            reviewId,
            domain,
            "sha256:review",
            source == AdminReviewSource.ExternalProvider ? AdminReviewTargetType.ProviderEvidence : AdminReviewTargetType.Url,
            reason,
            severity,
            AdminReviewStatus.Open,
            source,
            "scan-review",
            null,
            null,
            42,
            currentStatus,
            "Medium",
            summary,
            "Privacy-safe evidence summary.",
            createdAtUtc,
            createdAtUtc,
            null,
            null,
            null,
            null,
            null);

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
