using FluentValidation;
using FluentValidation.Results;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Verifies the MVP Site Safety Scan layer applies risk without overclaiming trust.
/// </summary>
[TestFixture]
public sealed class SiteSafetyScannerTests
{
    /// <summary>
    /// Unknown pages with no negative signals remain LimitedData instead of becoming trusted.
    /// </summary>
    [Test]
    public async Task Clean_unknown_site_returns_limited_data()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest("https://example.com"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(81));
            Assert.That(result.Summary, Does.Contain("limited trust data"));
        });
    }

    /// <summary>
    /// HTTPS is treated as a positive transport signal but never as proof that the page is safe.
    /// </summary>
    [Test]
    public async Task Https_alone_does_not_mark_site_trusted()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest("https://unknown-example.com"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.PositiveSignals, Has.Some.Contains("HTTPS"));
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Clean));
            Assert.That(result.FinalHipScore, Is.LessThanOrEqualTo(60));
        });
    }

    /// <summary>
    /// Executable download links carry materially higher safety risk than ordinary links.
    /// </summary>
    [Test]
    public async Task Executable_download_link_raises_download_risk()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://downloads.example.com",
                new SiteSafetyObservedSignals(DownloadLinks: ["https://downloads.example.com/update.exe"])),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DownloadRiskScore, Is.GreaterThanOrEqualTo(40));
            Assert.That(result.Status, Is.AnyOf(SiteSafetyScanStatus.Suspicious, SiteSafetyScanStatus.HighRisk));
            Assert.That(result.Warnings, Has.Some.Contains("executable"));
        });
    }

    /// <summary>
    /// Archive downloads require review but are not automatically classified as dangerous.
    /// </summary>
    [Test]
    public async Task Archive_download_link_is_review_needed_not_automatically_dangerous()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://files.example.com",
                new SiteSafetyObservedSignals(DownloadLinks: ["https://files.example.com/archive.zip"])),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DownloadRiskScore, Is.GreaterThan(0));
            Assert.That(result.DownloadRiskScore, Is.LessThan(45));
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
        });
    }

    /// <summary>
    /// Suspicious redirect observations increase redirect risk without the scanner following redirects itself.
    /// </summary>
    [Test]
    public async Task Suspicious_redirect_chain_raises_redirect_risk()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://example.com/login",
                new SiteSafetyObservedSignals(RedirectChain: ["https://tinyurl.com/win", "https://scam-prize.xyz"])),
            CancellationToken.None);

        Assert.That(result.RedirectRiskScore, Is.GreaterThanOrEqualTo(60));
    }

    /// <summary>
    /// Login forms on domains with limited trust data are caution-worthy without reading form values.
    /// </summary>
    [Test]
    public async Task Login_form_on_unknown_domain_raises_form_risk()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://signin.example.com",
                new SiteSafetyObservedSignals(HasLoginForm: true, HasPasswordField: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.FormRiskScore, Is.GreaterThanOrEqualTo(45));
            Assert.That(result.Warnings, Has.Some.Contains("login fields"));
        });
    }

    /// <summary>
    /// Privacy-safe scam wording signals raise phishing risk without sending full page text.
    /// </summary>
    [Test]
    public async Task Scam_wording_signal_raises_phishing_risk()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://promo.example.com",
                new SiteSafetyObservedSignals(ContainsScamWording: true)),
            CancellationToken.None);

        Assert.That(result.PhishingRiskScore, Is.GreaterThanOrEqualTo(55));
    }

    /// <summary>
    /// Confirmed phishing indicators use a built-in phishing rule and force a Dangerous status.
    /// </summary>
    [Test]
    public async Task Known_phishing_pattern_returns_dangerous()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://login-test.example",
                new SiteSafetyObservedSignals(KnownPhishingPattern: true, TrustDataAvailable: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "phishing-known-pattern"));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.StatusOverride == SiteSafetyScanStatus.Dangerous));
        });
    }

    /// <summary>
    /// Confirmed malware indicators force a dangerous result and lower the final HIP score.
    /// </summary>
    [Test]
    public async Task Confirmed_malware_indicator_returns_dangerous()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://malware-test.example",
                new SiteSafetyObservedSignals(KnownMalwareIndicator: true, TrustDataAvailable: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.FinalHipScore, Is.LessThan(60));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "malware-known-indicator"));
        });
    }

    /// <summary>
    /// Payment fields carry stronger form risk than ordinary login fields because financial loss impact is higher.
    /// </summary>
    [Test]
    public async Task Payment_field_raises_stronger_form_risk()
    {
        var loginResult = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://signin.example.com",
                new SiteSafetyObservedSignals(HasLoginForm: true)),
            CancellationToken.None);
        var paymentResult = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://checkout.example.com",
                new SiteSafetyObservedSignals(HasPaymentField: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(paymentResult.FormRiskScore, Is.GreaterThan(loginResult.FormRiskScore));
            Assert.That(paymentResult.Warnings, Has.Some.Contains("payment fields"));
            Assert.That(paymentResult.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "form-payment-limited-data"));
        });
    }

    /// <summary>
    /// Missing HTTPS is represented as a built-in rule warning and modest risk impact, not as an automatic block.
    /// </summary>
    [Test]
    public async Task Missing_https_adds_warning()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest("http://example.com"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Warnings, Has.Some.Contains("does not use HTTPS"));
            Assert.That(result.PhishingRiskScore, Is.GreaterThanOrEqualTo(20));
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.MatchedRules, Has.Some.Matches<SiteSafetyRuleResult>(rule => rule.RuleId == "transport-https-missing"));
        });
    }

    /// <summary>
    /// Matched rule results expose explainable built-in rule metadata without leaking private page content.
    /// </summary>
    [Test]
    public async Task Matched_rules_are_included_with_builtin_metadata()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://example.com/download",
                new SiteSafetyObservedSignals(DownloadLinks: ["https://example.com/tool.exe"])),
            CancellationToken.None);

        var matchedRule = result.MatchedRules!.Single(rule => rule.RuleId == "download-executable");

        Assert.Multiple(() =>
        {
            Assert.That(matchedRule.RuleName, Is.EqualTo("Executable download"));
            Assert.That(matchedRule.Source, Is.EqualTo(SiteSafetyRuleSource.BuiltIn));
            Assert.That(matchedRule.RiskImpact, Is.GreaterThanOrEqualTo(40));
            Assert.That(matchedRule.Warning, Does.Contain("executable files"));
        });
    }

    /// <summary>
    /// Unexpected scanner failures return ScanFailed so no trust boost is accidentally granted.
    /// </summary>
    [Test]
    public async Task Failed_scan_returns_scan_failed_status()
    {
        var scanner = new SiteSafetyScanner(
            new ThrowingSiteSafetyValidator(),
            NullLogger<SiteSafetyScanner>.Instance);

        var result = await scanner.ScanAsync(
            new SiteSafetyScanRequest("https://example.com"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.ScanFailed));
            Assert.That(result.FinalHipScore, Is.EqualTo(50));
        });
    }

    /// <summary>
    /// Site safety risk changes page, content, and final HIP scores without replacing the whole scoring model.
    /// </summary>
    [Test]
    public async Task Site_safety_risk_has_score_impact()
    {
        var result = await CreateScanner().ScanAsync(
            new SiteSafetyScanRequest(
                "https://example.xyz",
                new SiteSafetyObservedSignals(ContainsScamWording: true, DownloadLinks: ["https://example.xyz/run.exe"])),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.PageTrustScore, Is.LessThan(60));
            Assert.That(result.ContentRiskScore, Is.GreaterThan(0));
            Assert.That(result.DomainTrustScore, Is.InRange(0, 100));
            Assert.That(result.FinalHipScore, Is.InRange(0, 100));
            Assert.That(result.ScoreImpact.ScoreBreakdown, Has.Count.EqualTo(3));
        });
    }

    /// <summary>
    /// Creates the scanner with its production validator and a null logger for deterministic unit tests.
    /// </summary>
    private static SiteSafetyScanner CreateScanner() =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance);

    /// <summary>
    /// Test-only validator that simulates unexpected infrastructure failure.
    /// </summary>
    private sealed class ThrowingSiteSafetyValidator : AbstractValidator<SiteSafetyScanRequest>
    {
        /// <summary>
        /// Throws during validation so the scanner's safe failure path can be verified.
        /// </summary>
        /// <param name="context">Validation context.</param>
        /// <param name="cancellation">Cancellation token.</param>
        /// <returns>This method always throws.</returns>
        public override Task<ValidationResult> ValidateAsync(ValidationContext<SiteSafetyScanRequest> context, CancellationToken cancellation = default) =>
            throw new InvalidOperationException("Simulated validator failure.");
    }
}
