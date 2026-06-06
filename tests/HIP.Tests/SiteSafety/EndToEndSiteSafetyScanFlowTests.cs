using FluentValidation;
using HIP.Application.Browser;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.SiteSafety;
using HIP.Domain.Audit;
using HIP.Domain.Reputation;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Verifies the end-to-end HIP Site Safety flow using service-level tests instead of browser automation.
/// </summary>
[TestFixture]
public sealed class EndToEndSiteSafetyScanFlowTests
{
    /// <summary>
    /// Unknown clean pages stay limited because absence of bad signals is not proof of trust.
    /// </summary>
    [Test]
    public async Task Unknown_clean_site_returns_limited_or_unknown_result()
    {
        var result = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://unknown-clean-flow.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.AnyOf(SiteSafetyScanStatus.LimitedData, SiteSafetyScanStatus.Unknown));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
            Assert.That(result.Summary, Does.Contain("limited trust data"));
        });
    }

    /// <summary>
    /// Browser observations expose only structural facts, which keeps the server from crawling or receiving private page content in MVP.
    /// </summary>
    [Test]
    public void Browser_observed_signal_payload_is_privacy_safe()
    {
        var propertyNames = typeof(SiteSafetyObservedSignals).GetProperties().Select(property => property.Name).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(propertyNames, Does.Contain(nameof(SiteSafetyObservedSignals.HasLoginForm)));
            Assert.That(propertyNames, Does.Contain(nameof(SiteSafetyObservedSignals.HasPasswordField)));
            Assert.That(propertyNames, Does.Contain(nameof(SiteSafetyObservedSignals.DownloadLinks)));
            Assert.That(propertyNames, Does.Not.Contain("PageText"));
            Assert.That(propertyNames, Does.Not.Contain("FormValues"));
            Assert.That(propertyNames, Does.Not.Contain("PasswordValue"));
            Assert.That(propertyNames, Does.Not.Contain("EmailContent"));
        });
    }

    /// <summary>
    /// GitHub's homepage can earn high domain trust without becoming dangerous.
    /// </summary>
    [Test]
    public async Task Github_homepage_returns_high_domain_trust_without_dangerous_label()
    {
        var result = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://github.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.GreaterThanOrEqualTo(85));
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.FinalHipScore, Is.LessThanOrEqualTo(result.DomainTrustScore));
        });
    }

    /// <summary>
    /// Trusted domains with risky page or content observations produce a mixed layered result.
    /// </summary>
    [Test]
    public async Task Github_risky_repo_returns_mixed_layered_result()
    {
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://github.com/random-user/free-cracked-tool",
                new SiteSafetyObservedSignals(
                    DownloadLinks: ["https://github.com/random-user/free-cracked-tool/releases/download/v1/tool.exe"],
                    MatchedRiskTerms: ["CrackedSoftware", "DisableAntivirus"])),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.GreaterThanOrEqualTo(85));
            Assert.That(result.PageTrustScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.ContentRiskScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.FinalHipScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.Warnings, Is.Not.Empty);
        });
    }

    /// <summary>
    /// Executable download observations raise content risk without trusting the parent page by default.
    /// </summary>
    [Test]
    public async Task Executable_download_raises_content_risk()
    {
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://downloads.example",
                new SiteSafetyObservedSignals(DownloadLinks: ["https://downloads.example/setup.exe"])),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DownloadRiskScore, Is.GreaterThanOrEqualTo(45));
            Assert.That(result.ContentRiskScore, Is.LessThanOrEqualTo(70));
            Assert.That(result.Warnings, Has.Some.Contains("executable"));
        });
    }

    /// <summary>
    /// Login forms on unknown domains create warnings from structural form facts only.
    /// </summary>
    [Test]
    public async Task Login_form_on_unknown_domain_raises_warning()
    {
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://signin-flow.example",
                new SiteSafetyObservedSignals(HasLoginForm: true, HasPasswordField: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.FormRiskScore, Is.GreaterThanOrEqualTo(45));
            Assert.That(result.Warnings, Has.Some.Contains("login fields"));
            Assert.That(string.Join(" ", result.Reasons), Does.Not.Contain("password value"));
        });
    }

    /// <summary>
    /// Provider timeouts are captured as normalized evidence errors and do not crash the scan flow.
    /// </summary>
    [Test]
    public async Task Provider_timeout_does_not_crash_scan_flow()
    {
        var result = await Scanner(new TimeoutProvider()).ScanAsync(new SiteSafetyScanRequest("https://timeout-flow.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.ScanFailed));
            Assert.That(result.ProviderEvidence.SelectMany(evidence => evidence.Errors), Has.Some.Contains("timed out"));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
        });
    }

    /// <summary>
    /// SSL Labs / Qualys-style TLS evidence is enabled by default, while credentialed providers stay disabled.
    /// </summary>
    [Test]
    public void Ssl_labs_provider_is_enabled_by_default_and_credentialed_providers_remain_disabled()
    {
        var options = new ExternalSiteEvidenceOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.ExternalProvidersEnabled, Is.True);
            Assert.That(options.SslLabs.Enabled, Is.True);
            Assert.That(options.GoogleWebRisk.Enabled, Is.False);
            Assert.That(options.VirusTotal.Enabled, Is.False);
        });
    }

    /// <summary>
    /// Feedback is weighted evidence, not voting, so anonymous feedback moves reputation lightly.
    /// </summary>
    [Test]
    public async Task Feedback_affects_confidence_and_reputation_lightly()
    {
        var service = new ReputationService(new InMemoryReputationEventRepository(), new InMemoryReputationProfileRepository());

        var profile = await service.SubmitFeedbackAsync(
            new ReputationFeedbackRequest(
                ReputationSubjectType.Domain,
                "feedback-flow.example",
                ReputationEventType.SuspiciousReport,
                ReputationEventSeverity.Medium,
                ReporterTrustLevel.Anonymous,
                "Privacy-safe suspicious feedback label.",
                "BrowserPluginBanner",
                "sha256:url"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(profile.CurrentScore, Is.GreaterThan(70));
            Assert.That(profile.EventCount, Is.EqualTo(1));
            Assert.That(profile.Explanations, Has.Some.Contains("privacy-safe reputation event"));
        });
    }

    /// <summary>
    /// High-risk low-confidence results are routed into the admin review queue for human judgment.
    /// </summary>
    [Test]
    public async Task Review_signal_is_created_for_high_risk_low_confidence_case()
    {
        var reviewService = ReviewQueue();
        var scan = ScanResult(
            SiteSafetyScanStatus.HighRisk,
            confidenceLevel: "Low",
            finalScore: 18,
            summary: "High-risk low-confidence scan should be reviewed.");

        var items = await reviewService.CreateSignalsFromScanAsync(scan, CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("HighRiskLowConfidence"));
    }

    /// <summary>
    /// Popup score responses carry the full layered scoring fields required by the extension details panel.
    /// </summary>
    [Test]
    public void Popup_score_response_contains_required_fields()
    {
        var propertyNames = typeof(BrowserScoreSiteResponse).GetProperties().Select(property => property.Name).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.Domain)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.Score)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.FinalHipScore)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.DomainTrustScore)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.PageTrustScore)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.ContentRiskScore)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.FinalHipScoreExplanation)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.Status)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.Reasons)));
            Assert.That(propertyNames, Does.Contain(nameof(BrowserScoreSiteResponse.PublicLookupUrl)));
        });
    }

    /// <summary>
    /// The extension keeps the popup as the primary UX and reserves banners for warning-level pages.
    /// </summary>
    [Test]
    public void Banner_policy_keeps_normal_clean_pages_out_of_the_injected_banner()
    {
        var source = ExtensionSource("src", "hipApiClient.js");

        Assert.Multiple(() =>
        {
            Assert.That(source, Does.Contain("The popup remains the default details surface"));
            Assert.That(source, Does.Contain("status === \"Suspicious\" || status === \"HighRisk\" || status === \"Dangerous\""));
            Assert.That(source, Does.Contain("status === \"LimitedTrustData\""));
            Assert.That(source, Does.Contain("return false;"));
        });
    }

    /// <summary>
    /// Creates a scanner with deterministic cache behavior for flow tests.
    /// </summary>
    /// <param name="providers">Optional normalized evidence providers.</param>
    /// <returns>A Site Safety scanner.</returns>
    private static SiteSafetyScanner Scanner(params ISiteSafetyEvidenceProvider[] providers) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, providers, new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero });

    /// <summary>
    /// Creates the generated admin review queue service for review-flow assertions.
    /// </summary>
    /// <returns>An admin review queue service backed by in-memory storage.</returns>
    private static AdminReviewQueueService ReviewQueue() =>
        new(new InMemoryAdminReviewQueueRepository(), new AdminReviewQueueItemValidator(), new AuditLogService());

    /// <summary>
    /// Builds a privacy-safe Site Safety result for review queue integration tests.
    /// </summary>
    /// <param name="status">Status label to include.</param>
    /// <param name="confidenceLevel">Confidence label to include.</param>
    /// <param name="finalScore">Final HIP score to include.</param>
    /// <param name="summary">Privacy-safe summary to include.</param>
    /// <returns>A Site Safety scan result.</returns>
    private static SiteSafetyScanResult ScanResult(SiteSafetyScanStatus status, string confidenceLevel, int finalScore, string summary) =>
        new(
            "scan-flow-test",
            "https://review-flow.example",
            "review-flow.example",
            DateTimeOffset.UtcNow,
            MalwareRiskScore: 0,
            PhishingRiskScore: status is SiteSafetyScanStatus.HighRisk ? 75 : 0,
            RedirectRiskScore: 0,
            ScriptRiskScore: 0,
            DownloadRiskScore: 0,
            FormRiskScore: 0,
            ReputationRiskScore: 0,
            OverallSafetyRiskScore: status is SiteSafetyScanStatus.HighRisk ? 75 : 0,
            status,
            summary,
            ["Privacy-safe scan reason."],
            ["Privacy-safe scan warning."],
            [],
            [],
            confidenceLevel,
            DomainTrustScore: 55,
            PageTrustScore: 35,
            ContentRiskScore: 40,
            finalScore,
            [],
            new SiteSafetyScoreImpact(55, 35, 40, finalScore, []),
            []);

    /// <summary>
    /// Reads browser extension source from the repository so UI policy tests do not need Chromium yet.
    /// </summary>
    /// <param name="segments">Path segments under the browser extension root.</param>
    /// <returns>Source file text.</returns>
    private static string ExtensionSource(params string[] segments)
    {
        var root = FindRepositoryRoot();
        var pathSegments = new[] { root, "clients", "browser-extension" }.Concat(segments).ToArray();
        return File.ReadAllText(Path.Combine(pathSegments));
    }

    /// <summary>
    /// Finds the repository root from the compiled test output path.
    /// </summary>
    /// <returns>Repository root path.</returns>
    /// <exception cref="DirectoryNotFoundException">Thrown if the repository root cannot be found.</exception>
    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP repository root.");
    }

    /// <summary>
    /// Evidence provider that simulates a timeout from an optional external provider.
    /// </summary>
    private sealed class TimeoutProvider : ISiteSafetyEvidenceProvider
    {
        /// <inheritdoc />
        public string ProviderName => "TimeoutProvider";

        /// <inheritdoc />
        public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.ThreatIntel;

        /// <inheritdoc />
        public Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken) =>
            throw new TimeoutException("Simulated timeout.");
    }
}
