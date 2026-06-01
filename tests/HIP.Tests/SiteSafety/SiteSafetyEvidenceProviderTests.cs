using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Tests the provider-based site safety evidence architecture and external scanner safeguards.
/// </summary>
[TestFixture]
public sealed class SiteSafetyEvidenceProviderTests
{
    /// <summary>
    /// Verifies third-party provider base classes do not call external scanners unless explicitly enabled.
    /// </summary>
    [Test]
    public async Task External_providers_are_disabled_by_default()
    {
        var provider = new TestExternalProvider(new InMemoryExternalSiteEvidenceCache(), new ExternalSiteEvidenceOptions());

        var evidence = await provider.CollectEvidenceAsync(Context(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(provider.ExternalCallCount, Is.EqualTo(0));
            Assert.That(evidence.Errors, Has.Some.Contains("disabled"));
            Assert.That(evidence.EvidenceItems, Is.Empty);
        });
    }

    /// <summary>
    /// Verifies provider timeout failures are captured as evidence errors instead of crashing scoring.
    /// </summary>
    [Test]
    public async Task Scanner_timeout_does_not_crash_scoring()
    {
        var scanner = CreateScanner(new TimeoutEvidenceProvider());

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://example.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.ScanFailed));
            Assert.That(result.ProviderEvidence.SelectMany(evidence => evidence.Errors), Has.Some.Contains("timed out"));
            Assert.That(result.ConfidenceLevel, Is.Not.EqualTo("High"));
        });
    }

    /// <summary>
    /// Verifies a strong TLS scanner result gives only a small trust boost and cannot make an unknown site trusted.
    /// </summary>
    [Test]
    public async Task Ssl_labs_a_grade_gives_only_small_boost()
    {
        var scanner = CreateScanner(new StaticEvidenceProvider(SslLabsEvidence("A", SiteSafetyEvidenceStatus.Positive, risk: 0, trust: 5)));

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://unknown-example.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.DomainTrustScore, Is.InRange(60, 63));
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
        });
    }

    /// <summary>
    /// Verifies weak TLS evidence lowers confidence rather than producing a fake trust boost.
    /// </summary>
    [Test]
    public async Task Weak_tls_lowers_confidence()
    {
        var scanner = CreateScanner(new StaticEvidenceProvider(SslLabsEvidence("F", SiteSafetyEvidenceStatus.Weak, risk: 25, trust: 0)));

        var result = await scanner.ScanAsync(
            new SiteSafetyScanRequest("https://example.com", new SiteSafetyObservedSignals(TrustDataAvailable: true)),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.ConfidenceLevel, Is.EqualTo("Medium"));
            Assert.That(result.Warnings, Has.Some.Contains("TLS"));
        });
    }

    /// <summary>
    /// Verifies authoritative threat-intel phishing evidence can force HighRisk or Dangerous output.
    /// </summary>
    [Test]
    public async Task Threat_intel_phishing_hit_forces_high_risk_or_dangerous()
    {
        var scanner = CreateScanner(new StaticEvidenceProvider(ThreatIntelEvidence("PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, 95)));

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://example.com/login"), CancellationToken.None);

        Assert.That(result.Status, Is.AnyOf(SiteSafetyScanStatus.HighRisk, SiteSafetyScanStatus.Dangerous));
    }

    /// <summary>
    /// Verifies a clean external scanner result does not make an unknown domain trusted.
    /// </summary>
    [Test]
    public async Task Clean_external_result_does_not_make_unknown_domain_trusted()
    {
        var scanner = CreateScanner(new StaticEvidenceProvider(SslLabsEvidence("Clean", SiteSafetyEvidenceStatus.Clean, risk: 0, trust: 25)));

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://acs.ca"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
        });
    }

    /// <summary>
    /// Verifies conflicting provider results lower confidence and produce a review warning.
    /// </summary>
    [Test]
    public async Task Conflicting_external_results_lower_confidence()
    {
        var scanner = CreateScanner(
            new StaticEvidenceProvider(SslLabsEvidence("Clean", SiteSafetyEvidenceStatus.Clean, risk: 0, trust: 5)),
            new StaticEvidenceProvider(ThreatIntelEvidence("PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, 95)));

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://example.com"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.ConfidenceLevel, Is.EqualTo("Low"));
            Assert.That(result.Warnings, Has.Some.Contains("conflicts"));
        });
    }

    /// <summary>
    /// Verifies normalized external evidence is cached and expires safely.
    /// </summary>
    [Test]
    public void External_evidence_is_cached_with_expiry()
    {
        var cache = new InMemoryExternalSiteEvidenceCache();
        var fresh = SslLabsEvidence("A", SiteSafetyEvidenceStatus.Positive, risk: 0, trust: 5);
        var expired = fresh with { ProviderName = "ExpiredProvider", ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1) };

        cache.Store(fresh);
        cache.Store(expired);

        Assert.Multiple(() =>
        {
            Assert.That(cache.GetFresh(fresh.ProviderName, fresh.Domain, fresh.UrlHash), Is.Not.Null);
            Assert.That(cache.GetFresh(expired.ProviderName, expired.Domain, expired.UrlHash), Is.Null);
        });
    }

    /// <summary>
    /// Creates a scanner with production validation and test evidence providers.
    /// </summary>
    private static SiteSafetyScanner CreateScanner(params ISiteSafetyEvidenceProvider[] providers) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, providers);

    /// <summary>
    /// Creates a privacy-safe provider context for direct provider tests.
    /// </summary>
    private static SiteSafetyEvidenceContext Context() =>
        new(new Uri("https://example.com"), "example.com", "hash", new SiteSafetyObservedSignals(), DateTimeOffset.UtcNow);

    /// <summary>
    /// Creates normalized SSL Labs-style evidence without calling SSL Labs.
    /// </summary>
    private static SiteSafetyEvidence SslLabsEvidence(string grade, SiteSafetyEvidenceStatus status, int risk, int trust) =>
        Evidence(
            "SSL Labs Test Provider",
            SiteSafetyEvidenceProviderType.TlsScanner,
            "TlsGrade",
            grade,
            status,
            risk,
            trust,
            status == SiteSafetyEvidenceStatus.Weak ? "TLS scanner reported weak TLS configuration." : "TLS scanner reported strong TLS configuration.",
            authoritativeRisk: false,
            authoritativeTrust: true);

    /// <summary>
    /// Creates normalized threat-intel evidence without calling any third-party threat feed.
    /// </summary>
    private static SiteSafetyEvidence ThreatIntelEvidence(string category, SiteSafetyEvidenceStatus status, int risk) =>
        Evidence(
            "Threat Intel Test Provider",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            category,
            "Hit",
            status,
            risk,
            trust: 0,
            "Threat-intel provider matched a phishing or malware indicator.",
            authoritativeRisk: true,
            authoritativeTrust: false);

    /// <summary>
    /// Creates normalized evidence used by test providers.
    /// </summary>
    private static SiteSafetyEvidence Evidence(
        string providerName,
        SiteSafetyEvidenceProviderType providerType,
        string category,
        string value,
        SiteSafetyEvidenceStatus status,
        int risk,
        int trust,
        string summary,
        bool authoritativeRisk,
        bool authoritativeTrust) =>
        new(
            providerName,
            providerType,
            SiteSafetyEvidenceTargetType.Domain,
            "example.com",
            "hash",
            [new SiteSafetyEvidenceItem(category, value, status, risk, trust, summary)],
            Confidence: 90,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddHours(1),
            [],
            authoritativeRisk,
            authoritativeTrust);

    /// <summary>
    /// Test provider that returns a fixed normalized evidence record.
    /// </summary>
    private sealed class StaticEvidenceProvider(SiteSafetyEvidence evidence) : ISiteSafetyEvidenceProvider
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
    /// Test provider that simulates an external timeout.
    /// </summary>
    private sealed class TimeoutEvidenceProvider : ISiteSafetyEvidenceProvider
    {
        /// <inheritdoc />
        public string ProviderName => "TimeoutProvider";

        /// <inheritdoc />
        public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.ThreatIntel;

        /// <inheritdoc />
        public Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken) =>
            throw new TimeoutException("Simulated timeout.");
    }

    /// <summary>
    /// Test external provider that records whether external collection was invoked.
    /// </summary>
    private sealed class TestExternalProvider(IExternalSiteEvidenceCache cache, ExternalSiteEvidenceOptions options)
        : ExternalSiteEvidenceProviderBase(cache, options)
    {
        /// <summary>
        /// Gets how many times the external scanner path was invoked.
        /// </summary>
        public int ExternalCallCount { get; private set; }

        /// <inheritdoc />
        public override string ProviderName => "TestExternalProvider";

        /// <inheritdoc />
        public override SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.ThreatIntel;

        /// <inheritdoc />
        protected override Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
        {
            ExternalCallCount++;
            return Task.FromResult(ThreatIntelEvidence("PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, 95));
        }
    }
}
