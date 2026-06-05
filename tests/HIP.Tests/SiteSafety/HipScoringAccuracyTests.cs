using System.Text.Json;
using FluentValidation;
using HIP.Application.Browser;
using HIP.Application.PublicLookup;
using HIP.Application.Reputation;
using HIP.Application.Reporting;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;
using HIP.Domain.Risk;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Regression tests for HIP's conservative layered scoring contract.
/// </summary>
[TestFixture]
public sealed class HipScoringAccuracyTests
{
    /// <summary>
    /// Strong known domains should earn high domain trust without becoming dangerous absent strong page risk.
    /// </summary>
    [Test]
    public async Task Github_homepage_scores_high_domain_trust_without_high_risk_label()
    {
        var service = await LookupWithStoredScanAsync("github.com", score: 84, status: "MostlyTrusted", linksScanned: 24);

        var result = await service.LookupDomainAsync("github.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.GreaterThanOrEqualTo(85));
            Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.HighRisk));
            Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.Dangerous));
            Assert.That(result.FinalHipScoreExplanation, Does.Contain("DomainTrustScore"));
        });
    }

    /// <summary>
    /// A GitHub repository page keeps high parent-domain trust but does not inherit full page trust.
    /// </summary>
    [Test]
    public async Task Github_unknown_repo_does_not_inherit_full_trust()
    {
        var service = await LookupWithStoredScanAsync("github.com", score: 84, status: "MostlyTrusted", linksScanned: 12);

        var result = await service.LookupDomainAsync("github.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.GreaterThanOrEqualTo(85));
            Assert.That(result.PageTrustScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.Status, Is.Not.EqualTo(RiskStatus.Trusted));
        });
    }

    /// <summary>
    /// Risky page/content signals on a trusted parent domain must lower final trust and explain the mixed case.
    /// </summary>
    [Test]
    public async Task Trusted_domain_with_risky_repo_content_scores_lower_and_explains_mixed_case()
    {
        var service = await LookupWithStoredScanAsync(
            "github.com",
            score: 50,
            status: "Suspicious",
            linksScanned: 18,
            riskyLinks: 3,
            suspiciousLinks: 2,
            dangerousLinks: 1,
            reasons: ["Executable download links were observed by the browser plugin."]);

        var result = await service.LookupDomainAsync("github.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.GreaterThanOrEqualTo(85));
            Assert.That(result.PageTrustScore, Is.LessThan(50));
            Assert.That(result.ContentRiskScore, Is.LessThan(50));
            Assert.That(result.FinalHipScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.FinalHipScoreExplanation, Does.Contain("parent domain has strong trust signals"));
        });
    }

    /// <summary>
    /// Unknown clean sites stay limited or unknown because no bad signals found is not proof of trust.
    /// </summary>
    [Test]
    public async Task Unknown_clean_site_is_not_trusted_or_mostly_trusted()
    {
        var result = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://unknown-clean.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
            Assert.That(result.Summary, Does.Contain("limited trust data"));
            Assert.That(result.Reasons, Has.Some.Contains("limited reputation history"));
        });
    }

    /// <summary>
    /// HTTPS is a transport signal only and cannot make an unknown site trusted.
    /// </summary>
    [Test]
    public async Task Https_only_site_does_not_score_trusted()
    {
        var result = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://https-only.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.PositiveSignals, Has.Some.Contains("HTTPS"));
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
        });
    }

    /// <summary>
    /// Login and payment fields on limited-trust sites must lower page trust and produce clear warnings.
    /// </summary>
    [Test]
    public async Task Unknown_site_with_login_and_payment_fields_raises_form_risk()
    {
        var login = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://signin.example", new SiteSafetyObservedSignals(HasLoginForm: true, HasPasswordField: true)), CancellationToken.None);
        var payment = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://checkout.example", new SiteSafetyObservedSignals(HasPaymentField: true)), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(login.FormRiskScore, Is.GreaterThanOrEqualTo(45));
            Assert.That(login.PageTrustScore, Is.LessThanOrEqualTo(60));
            Assert.That(login.Warnings, Has.Some.Contains("login fields"));
            Assert.That(payment.FormRiskScore, Is.GreaterThan(login.FormRiskScore));
            Assert.That(payment.Warnings, Has.Some.Contains("payment fields"));
        });
    }

    /// <summary>
    /// Download signals must not inherit full trust from a parent domain.
    /// </summary>
    [Test]
    public async Task Executable_and_archive_downloads_have_different_risk_strength()
    {
        var executable = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://files.example", new SiteSafetyObservedSignals(DownloadLinks: ["https://files.example/tool.exe"])), CancellationToken.None);
        var archive = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://files.example", new SiteSafetyObservedSignals(DownloadLinks: ["https://files.example/archive.zip"])), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(executable.DownloadRiskScore, Is.GreaterThanOrEqualTo(45));
            Assert.That(executable.Warnings, Has.Some.Contains("executable"));
            Assert.That(archive.DownloadRiskScore, Is.GreaterThan(0));
            Assert.That(archive.DownloadRiskScore, Is.LessThan(executable.DownloadRiskScore));
            Assert.That(archive.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
        });
    }

    /// <summary>
    /// Scam, urgency, and impersonation labels raise phishing risk without sending raw page text.
    /// </summary>
    [TestCase(nameof(SiteSafetyObservedSignals.ContainsScamWording))]
    [TestCase(nameof(SiteSafetyObservedSignals.ContainsUrgencyWording))]
    [TestCase(nameof(SiteSafetyObservedSignals.ContainsImpersonationWording))]
    public async Task Privacy_safe_risk_wording_labels_raise_phishing_risk(string signalName)
    {
        var signals = signalName switch
        {
            nameof(SiteSafetyObservedSignals.ContainsScamWording) => new SiteSafetyObservedSignals(ContainsScamWording: true),
            nameof(SiteSafetyObservedSignals.ContainsUrgencyWording) => new SiteSafetyObservedSignals(ContainsUrgencyWording: true),
            _ => new SiteSafetyObservedSignals(ContainsImpersonationWording: true)
        };

        var result = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://promo.example", signals), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.PhishingRiskScore, Is.GreaterThanOrEqualTo(55));
            Assert.That(result.Reasons, Has.Some.Contains("Risk wording labels"));
        });
    }

    /// <summary>
    /// Confirmed phishing and malware indicators force Dangerous with explicit warnings.
    /// </summary>
    [TestCase(true, false, "phishing")]
    [TestCase(false, true, "malware")]
    public async Task Confirmed_abuse_indicators_force_dangerous_with_warning(bool phishing, bool malware, string expectedWarning)
    {
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest("https://known-bad.example", new SiteSafetyObservedSignals(KnownPhishingPattern: phishing, KnownMalwareIndicator: malware, TrustDataAvailable: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.FinalHipScore, Is.LessThan(result.DomainTrustScore));
            Assert.That(result.Warnings, Has.Some.Contains(expectedWarning));
        });
    }

    /// <summary>
    /// Redirect and shortener observations raise redirect risk without the scanner crawling privately.
    /// </summary>
    [Test]
    public async Task Redirects_and_shorteners_raise_redirect_risk()
    {
        var redirect = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://example.com/login", new SiteSafetyObservedSignals(RedirectChain: ["https://tinyurl.com/a", "https://destination.example"])), CancellationToken.None);
        var shortener = await Scanner().ScanAsync(new SiteSafetyScanRequest("https://example.com/page", new SiteSafetyObservedSignals(ShortenedLinkCount: 1)), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(redirect.RedirectRiskScore, Is.GreaterThanOrEqualTo(60));
            Assert.That(shortener.RedirectRiskScore, Is.GreaterThanOrEqualTo(60));
            Assert.That(shortener.Reasons, Has.Some.Contains("hide the final destination"));
        });
    }

    /// <summary>
    /// External provider timeout is safe: no crash and no accidental trust.
    /// </summary>
    [Test]
    public async Task External_provider_timeout_does_not_crash_or_create_trust()
    {
        var result = await Scanner(new TimeoutProvider()).ScanAsync(new SiteSafetyScanRequest("https://example.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.ScanFailed));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
            Assert.That(result.ProviderEvidence.SelectMany(evidence => evidence.Errors), Has.Some.Contains("timed out"));
        });
    }

    /// <summary>
    /// Clean external results and strong TLS grades provide limited help only, never full trust.
    /// </summary>
    [Test]
    public async Task Clean_external_and_ssl_a_grade_do_not_make_unknown_site_trusted()
    {
        var clean = await Scanner(new StaticProvider(Evidence("CleanScanner", SiteSafetyEvidenceProviderType.UrlReputation, "Clean", SiteSafetyEvidenceStatus.Clean, risk: 0, trust: 30, authoritativeTrust: true))).ScanAsync(new SiteSafetyScanRequest("https://clean.example"), CancellationToken.None);
        var sslA = await Scanner(new StaticProvider(Evidence("SSL Labs", SiteSafetyEvidenceProviderType.TlsScanner, "TlsGrade", SiteSafetyEvidenceStatus.Positive, risk: 0, trust: 5, authoritativeTrust: true))).ScanAsync(new SiteSafetyScanRequest("https://tls.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(clean.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(clean.FinalHipScore, Is.LessThan(70));
            Assert.That(sslA.DomainTrustScore, Is.LessThan(65));
            Assert.That(sslA.FinalHipScore, Is.LessThan(70));
        });
    }

    /// <summary>
    /// Weak TLS lowers confidence while threat-intel and VirusTotal-style hits raise risk.
    /// </summary>
    [Test]
    public async Task External_provider_risk_cases_affect_status_and_confidence()
    {
        var weakTls = await Scanner(new StaticProvider(Evidence("SSL Labs", SiteSafetyEvidenceProviderType.TlsScanner, "TlsGrade", SiteSafetyEvidenceStatus.Weak, risk: 25, trust: 0))).ScanAsync(new SiteSafetyScanRequest("https://weak-tls.example", new SiteSafetyObservedSignals(TrustDataAvailable: true)), CancellationToken.None);
        var phishing = await Scanner(new StaticProvider(Evidence("Google Web Risk", SiteSafetyEvidenceProviderType.ThreatIntel, "PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, risk: 95, trust: 0, authoritativeRisk: true))).ScanAsync(new SiteSafetyScanRequest("https://phishing.example"), CancellationToken.None);
        var virusTotal = await Scanner(new StaticProvider(Evidence("VirusTotal", SiteSafetyEvidenceProviderType.UrlReputation, "MalwareMatch", SiteSafetyEvidenceStatus.Dangerous, risk: 95, trust: 0, authoritativeRisk: true))).ScanAsync(new SiteSafetyScanRequest("https://malware.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(weakTls.ConfidenceLevel, Is.Not.EqualTo("High"));
            Assert.That(phishing.Status, Is.AnyOf(SiteSafetyScanStatus.HighRisk, SiteSafetyScanStatus.Dangerous));
            Assert.That(virusTotal.Status, Is.AnyOf(SiteSafetyScanStatus.HighRisk, SiteSafetyScanStatus.Dangerous));
        });
    }

    /// <summary>
    /// Conflicting external evidence lowers confidence and adds a plain-English warning.
    /// </summary>
    [Test]
    public async Task Conflicting_external_evidence_lowers_confidence()
    {
        var result = await Scanner(
            new StaticProvider(Evidence("CleanProvider", SiteSafetyEvidenceProviderType.TlsScanner, "TlsGrade", SiteSafetyEvidenceStatus.Clean, risk: 0, trust: 5, authoritativeTrust: true)),
            new StaticProvider(Evidence("ThreatProvider", SiteSafetyEvidenceProviderType.ThreatIntel, "PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, risk: 95, trust: 0, authoritativeRisk: true)))
            .ScanAsync(new SiteSafetyScanRequest("https://mixed.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.ConfidenceLevel, Is.EqualTo("Low"));
            Assert.That(result.Warnings, Has.Some.Contains("conflicts"));
        });
    }

    /// <summary>
    /// Weighted feedback must not behave like raw voting.
    /// </summary>
    [Test]
    public async Task Feedback_weighting_is_conservative()
    {
        var anonymousSuspicious = CreateReputationService();
        var adminSuspicious = CreateReputationService();
        var anonymousSafe = CreateReputationService();
        var manyLowTrust = CreateReputationService();

        var anonBad = await anonymousSuspicious.SubmitFeedbackAsync(Feedback("anon.example", ReputationEventType.SuspiciousReport, -20, ReporterTrustLevel.Anonymous), CancellationToken.None);
        var adminBad = await adminSuspicious.SubmitFeedbackAsync(Feedback("admin.example", ReputationEventType.SuspiciousReport, -20, ReporterTrustLevel.Admin), CancellationToken.None);
        var anonSafe = await anonymousSafe.SubmitFeedbackAsync(Feedback("safe.example", ReputationEventType.PositiveReport, 10, ReporterTrustLevel.Anonymous), CancellationToken.None);
        for (var index = 0; index < 12; index++)
        {
            await manyLowTrust.SubmitFeedbackAsync(Feedback("pile-on.example", ReputationEventType.SuspiciousReport, -5, ReporterTrustLevel.KnownFalseReporter), CancellationToken.None);
        }

        var pileOn = await manyLowTrust.GetProfileAsync(ReputationSubjectType.Domain, "pile-on.example", CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(anonBad.CurrentScore, Is.GreaterThan(adminBad.CurrentScore));
            Assert.That(anonSafe.CurrentScore, Is.GreaterThanOrEqualTo(HIP.Application.Reputation.ReputationService.DefaultScore));
            Assert.That(pileOn.Status, Is.Not.EqualTo(RiskStatus.Dangerous));
        });
    }

    /// <summary>
    /// Admin rule modes enforce only after approval and never when disabled, simulation, or watch-only.
    /// </summary>
    [Test]
    public async Task Admin_rule_modes_affect_scores_only_when_enforced_and_approved()
    {
        var disabled = await ScanWithAdminRule(AdminRule("disabled-rule") with { Status = AdminSiteSafetyRuleStatus.Disabled });
        var simulation = await ScanWithAdminRule(AdminRule("simulation-rule") with { Mode = AdminSiteSafetyRuleMode.Simulation });
        var watch = await ScanWithAdminRule(AdminRule("watch-rule") with { Mode = AdminSiteSafetyRuleMode.WatchOnly });
        var enforced = await ScanWithAdminRule(AdminRule("enforced-rule"));
        var dangerous = await ScanWithAdminRule(AdminRule("dangerous-rule") with { Severity = SiteSafetyRuleSeverity.High, Effects = new AdminSiteSafetyRuleEffects(SetStatusOverride: SiteSafetyScanStatus.Dangerous, AddWarning: "Approved dangerous override.") });

        Assert.Multiple(() =>
        {
            Assert.That(disabled.DownloadRiskScore, Is.EqualTo(0));
            Assert.That(simulation.DownloadRiskScore, Is.EqualTo(0));
            Assert.That(watch.DownloadRiskScore, Is.EqualTo(0));
            Assert.That(enforced.DownloadRiskScore, Is.EqualTo(60));
            Assert.That(dangerous.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
        });
    }

    /// <summary>
    /// Results include the required score fields, reasons, warnings, and no private raw content.
    /// </summary>
    [Test]
    public async Task Scoring_result_is_layered_explainable_and_privacy_safe()
    {
        var privateMarker = "secret-password-token-cookie-private-message";
        var result = await Scanner().ScanAsync(
            new SiteSafetyScanRequest(
                $"https://privacy.example/login?token={privateMarker}",
                new SiteSafetyObservedSignals(HasPasswordField: true, DownloadLinks: ["https://privacy.example/tool.exe"])),
            CancellationToken.None);
        var serialized = JsonSerializer.Serialize(result);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.InRange(0, 100));
            Assert.That(result.PageTrustScore, Is.InRange(0, 100));
            Assert.That(result.ContentRiskScore, Is.InRange(0, 100));
            Assert.That(result.FinalHipScore, Is.InRange(0, 100));
            Assert.That(result.ConfidenceLevel, Is.Not.Empty);
            Assert.That(result.Reasons, Is.Not.Empty);
            Assert.That(result.Warnings, Is.Not.Empty);
            Assert.That(serialized, Does.Not.Contain(privateMarker));
            Assert.That(serialized, Does.Not.Contain("page body text"));
            Assert.That(serialized, Does.Not.Contain("typed-form-value"));
        });
    }

    /// <summary>
    /// Creates a scanner with optional provider and admin-rule dependencies.
    /// </summary>
    private static SiteSafetyScanner Scanner(params ISiteSafetyEvidenceProvider[] providers) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, providers, new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero });

    /// <summary>
    /// Creates a scanner that uses an admin rule repository.
    /// </summary>
    private static SiteSafetyScanner Scanner(IAdminSiteSafetyRuleRepository repository) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, [], new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero }, repository);

    /// <summary>
    /// Creates a lookup service seeded with one privacy-safe browser scan summary.
    /// </summary>
    private static async Task<PublicDomainLookupService> LookupWithStoredScanAsync(
        string domain,
        int score,
        string status,
        int linksScanned = 0,
        int riskyLinks = 0,
        int suspiciousLinks = 0,
        int dangerousLinks = 0,
        IReadOnlyCollection<string>? reasons = null)
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var service = new BrowserScanResultService(repository, new Sha256PrivacyHashingService());
        await service.SaveAsync(new BrowserScanResultSaveRequest(
            domain,
            $"https://{domain}/some-user/some-repo?token=secret",
            score,
            status,
            status,
            reasons ?? ["Privacy-safe browser scan summary."],
            linksScanned,
            riskyLinks,
            suspiciousLinks,
            dangerousLinks,
            status is "Dangerous" or "HighRisk" ? "RouteToSafetyPage" : "Allow",
            new Dictionary<string, string> { ["source"] = "accuracy-test" }), CancellationToken.None);

        return new PublicDomainLookupService(repository);
    }

    /// <summary>
    /// Creates provider evidence for external scoring tests without calling third-party services.
    /// </summary>
    private static SiteSafetyEvidence Evidence(
        string providerName,
        SiteSafetyEvidenceProviderType providerType,
        string category,
        SiteSafetyEvidenceStatus status,
        int risk,
        int trust,
        bool authoritativeRisk = false,
        bool authoritativeTrust = false) =>
        new(
            providerName,
            providerType,
            SiteSafetyEvidenceTargetType.Domain,
            "example.com",
            "hash",
            [new SiteSafetyEvidenceItem(category, "Hit", status, risk, trust, $"{providerName} returned {status} evidence.", Confidence: 90, IsNegativeSignal: risk > 0, IsPositiveSignal: trust > 0, IsBlockingSignal: risk >= 90)],
            Confidence: 90,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1),
            [],
            authoritativeRisk,
            authoritativeTrust);

    /// <summary>
    /// Creates a reputation service for weighted feedback assertions.
    /// </summary>
    private static ReputationService CreateReputationService() =>
        new(new InMemoryReputationEventRepository(), new InMemoryReputationProfileRepository());

    /// <summary>
    /// Creates privacy-safe feedback without raw chat logs or page text.
    /// </summary>
    private static ReputationFeedbackRequest Feedback(string targetId, ReputationEventType type, int scoreImpact, ReporterTrustLevel trustLevel) =>
        new(ReputationSubjectType.Domain, targetId, type, ReputationEventSeverity.Medium, trustLevel, "Privacy-safe feedback label.", "BrowserPluginBanner", "sha256:url");

    /// <summary>
    /// Runs a scan with a single admin rule.
    /// </summary>
    private static async Task<SiteSafetyScanResult> ScanWithAdminRule(AdminSiteSafetyRule rule)
    {
        var repository = new InMemoryAdminSiteSafetyRuleRepository();
        await repository.SaveAsync(rule, CancellationToken.None);
        return await Scanner(repository).ScanAsync(new SiteSafetyScanRequest("https://admin-rule.example"), CancellationToken.None);
    }

    /// <summary>
    /// Creates an approved enforced admin rule that matches the test domain.
    /// </summary>
    private static AdminSiteSafetyRule AdminRule(string ruleId) =>
        new(
            ruleId,
            ruleId,
            "Accuracy test admin rule.",
            AdminSiteSafetyRuleTargetType.PageContent,
            [new AdminSiteSafetyRuleCondition("Domain", AdminSiteSafetyRuleOperator.EndsWith, JsonSerializer.SerializeToElement(".example"))],
            new AdminSiteSafetyRuleEffects(IncreaseDownloadRisk: 60, AddReason: "Approved admin rule matched."),
            SiteSafetyRuleSeverity.High,
            SiteSafetyEvidenceQuality.Strong,
            AdminSiteSafetyRuleStatus.Active,
            AdminSiteSafetyRuleMode.Enforced,
            "owner",
            DateTimeOffset.UtcNow,
            "owner",
            DateTimeOffset.UtcNow,
            1,
            null,
            false);

    /// <summary>
    /// Static provider used to inject normalized evidence into scanner tests.
    /// </summary>
    private sealed class StaticProvider(SiteSafetyEvidence evidence) : ISiteSafetyEvidenceProvider
    {
        /// <inheritdoc />
        public string ProviderName => evidence.ProviderName;

        /// <inheritdoc />
        public SiteSafetyEvidenceProviderType ProviderType => evidence.ProviderType;

        /// <inheritdoc />
        public Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken) =>
            Task.FromResult(evidence with { Domain = context.Domain, UrlHash = context.UrlHash });
    }

    /// <summary>
    /// Provider that simulates timeout failure without crashing the scanner.
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
