using HIP.Application.Reputation;
using HIP.Application.Security;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;

namespace HIP.Tests.Security;

/// <summary>
/// Covers HIP policy objects that protect privacy, external scanner usage, and feedback weighting.
/// </summary>
public sealed class HipPolicyObjectsTests
{
    /// <summary>
    /// Verifies HIP refuses empty metadata keys because they cannot be audited safely.
    /// </summary>
    [Test]
    public void Privacy_policy_rejects_empty_metadata_key()
    {
        var policy = new DefaultPrivacyStoragePolicy();

        var decision = policy.CanStoreMetadataKey(" ");

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("cannot be empty"));
    }

    /// <summary>
    /// Verifies HIP blocks private metadata fields that could contain message text, credentials, or raw browsing data.
    /// </summary>
    [TestCase("pageText")]
    [TestCase("formValues")]
    [TestCase("password")]
    [TestCase("cookie")]
    [TestCase("rawUrl")]
    public void Privacy_policy_rejects_private_metadata_keys(string key)
    {
        var policy = new DefaultPrivacyStoragePolicy();

        var decision = policy.CanStoreMetadataKey(key);

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("not privacy-safe"));
    }

    /// <summary>
    /// Verifies HIP allows public-safe summary metadata such as risk labels and provider names.
    /// </summary>
    [Test]
    public void Privacy_policy_allows_safe_metadata_key()
    {
        var policy = new DefaultPrivacyStoragePolicy();

        var decision = policy.CanStoreMetadataKey("providerName");

        Assert.That(decision.Allowed, Is.EqualTo(true));
        Assert.That(decision.Reason, Is.EqualTo("Metadata key is privacy-safe."));
    }

    /// <summary>
    /// Verifies metadata values are trimmed and bounded before storage.
    /// </summary>
    [Test]
    public void Privacy_policy_sanitizes_metadata_value()
    {
        var policy = new DefaultPrivacyStoragePolicy();

        var sanitized = policy.SanitizeMetadataValue("  abcdef  ", 3);

        Assert.That(sanitized, Is.EqualTo("abc"));
    }

    /// <summary>
    /// Verifies raw URL storage stays disabled by default to avoid leaking private browsing context.
    /// </summary>
    [Test]
    public void Privacy_policy_rejects_raw_url_storage()
    {
        var policy = new DefaultPrivacyStoragePolicy();

        var decision = policy.CanStoreRawUrl("BrowserScanResult");

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("URL hash"));
    }

    /// <summary>
    /// Verifies external provider submission is blocked when the global provider switch is off.
    /// </summary>
    [Test]
    public void Provider_policy_blocks_when_external_providers_are_globally_disabled()
    {
        var policy = new DefaultProviderSubmissionPolicy();
        var globalOptions = new ExternalSiteEvidenceOptions { ExternalProvidersEnabled = false };
        var providerOptions = new ExternalProviderOptions { Enabled = true };

        var decision = policy.CanSubmit("SSL Labs", CreateEvidenceContext(), globalOptions, providerOptions);

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("disabled by configuration"));
    }

    /// <summary>
    /// Verifies a provider-specific disable switch prevents external calls even when global providers are enabled.
    /// </summary>
    [Test]
    public void Provider_policy_blocks_when_provider_is_disabled()
    {
        var policy = new DefaultProviderSubmissionPolicy();
        var globalOptions = new ExternalSiteEvidenceOptions { ExternalProvidersEnabled = true };
        var providerOptions = new ExternalProviderOptions { Enabled = false };

        var decision = policy.CanSubmit("VirusTotal", CreateEvidenceContext(), globalOptions, providerOptions);

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("disabled by provider configuration"));
    }

    /// <summary>
    /// Verifies HIP blocks full URL provider checks unless a host explicitly allows that privacy tradeoff.
    /// </summary>
    [Test]
    public void Provider_policy_blocks_full_url_provider_when_full_url_checks_are_disabled()
    {
        var policy = new DefaultProviderSubmissionPolicy();
        var globalOptions = new ExternalSiteEvidenceOptions
        {
            ExternalProvidersEnabled = true,
            AllowFullUrlChecks = false
        };
        var providerOptions = new ExternalProviderOptions
        {
            Enabled = true,
            AllowFullUrl = true
        };

        var decision = policy.CanSubmit("Google Web Risk", CreateEvidenceContext(), globalOptions, providerOptions);

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("domain/hash checks only"));
    }

    /// <summary>
    /// Verifies provider calls require a normalized domain so HIP never submits vague or private page context.
    /// </summary>
    [Test]
    public void Provider_policy_blocks_missing_domain()
    {
        var policy = new DefaultProviderSubmissionPolicy();
        var globalOptions = new ExternalSiteEvidenceOptions { ExternalProvidersEnabled = true };
        var providerOptions = new ExternalProviderOptions { Enabled = true };

        var decision = policy.CanSubmit("SSL Labs", CreateEvidenceContext(domain: " "), globalOptions, providerOptions);

        Assert.That(decision.Allowed, Is.EqualTo(false));
        Assert.That(decision.Reason, Does.Contain("normalized domain is required"));
    }

    /// <summary>
    /// Verifies provider calls are allowed when they use the intended privacy-safe domain/hash context.
    /// </summary>
    [Test]
    public void Provider_policy_allows_privacy_safe_domain_hash_context()
    {
        var policy = new DefaultProviderSubmissionPolicy();
        var globalOptions = new ExternalSiteEvidenceOptions
        {
            ExternalProvidersEnabled = true,
            AllowFullUrlChecks = false
        };
        var providerOptions = new ExternalProviderOptions
        {
            Enabled = true,
            AllowFullUrl = false
        };

        var decision = policy.CanSubmit("SSL Labs", CreateEvidenceContext(), globalOptions, providerOptions);

        Assert.That(decision.Allowed, Is.EqualTo(true));
        Assert.That(decision.Reason, Is.EqualTo("Provider may run with privacy-safe domain/hash context."));
    }

    /// <summary>
    /// Verifies anonymous browser feedback has minimal weight because it is only weak supporting evidence.
    /// </summary>
    [Test]
    public void Feedback_policy_weights_anonymous_browser_feedback_as_weak()
    {
        var policy = new DefaultFeedbackWeightingPolicy();

        var weight = policy.CalculateWeight(HipFeedbackType.LooksSafe, ReporterTrustLevel.Anonymous, HipFeedbackSource.BrowserPluginBanner);

        Assert.That(weight, Is.EqualTo(1));
    }

    /// <summary>
    /// Verifies admin issue feedback is bounded so one feedback item cannot dominate scoring by itself.
    /// </summary>
    [Test]
    public void Feedback_policy_clamps_admin_issue_feedback()
    {
        var policy = new DefaultFeedbackWeightingPolicy();

        var weight = policy.CalculateWeight(HipFeedbackType.ReportIssue, ReporterTrustLevel.Admin, HipFeedbackSource.AdminPortal);

        Assert.That(weight, Is.EqualTo(12));
    }

    /// <summary>
    /// Verifies known low-quality reporters remain at the minimum evidence weight.
    /// </summary>
    [Test]
    public void Feedback_policy_keeps_known_false_reporter_at_minimum_weight()
    {
        var policy = new DefaultFeedbackWeightingPolicy();

        var weight = policy.CalculateWeight(HipFeedbackType.LooksSuspicious, ReporterTrustLevel.KnownFalseReporter, HipFeedbackSource.BrowserPluginPopup);

        Assert.That(weight, Is.EqualTo(1));
    }

    /// <summary>
    /// Verifies verified admin-portal issue reports get more weight while staying below admin-level authority.
    /// </summary>
    [Test]
    public void Feedback_policy_combines_trust_source_and_issue_weight()
    {
        var policy = new DefaultFeedbackWeightingPolicy();

        var weight = policy.CalculateWeight(HipFeedbackType.ReportIssue, ReporterTrustLevel.Verified, HipFeedbackSource.AdminPortal);

        Assert.That(weight, Is.EqualTo(6));
    }

    /// <summary>
    /// Builds a provider evidence context that contains only domain, URL hash, and privacy-safe observed signals.
    /// </summary>
    /// <param name="domain">Domain to place in the context.</param>
    /// <returns>Evidence context for provider policy tests.</returns>
    private static SiteSafetyEvidenceContext CreateEvidenceContext(string domain = "example.com") =>
        new(
            new Uri("https://example.com/login"),
            domain,
            "sha256-demo",
            new SiteSafetyObservedSignals(),
            DateTimeOffset.Parse("2026-06-19T00:00:00Z"));
}
