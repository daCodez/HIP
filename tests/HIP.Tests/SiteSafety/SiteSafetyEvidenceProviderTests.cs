using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Tests the provider-based site safety evidence architecture and external scanner safeguards.
/// </summary>
[TestFixture]
public sealed class SiteSafetyEvidenceProviderTests
{
    /// <summary>
    /// Verifies observed signal URL collections are stripped to public-safe origin/path values before scoring.
    /// </summary>
    [Test]
    public void Observed_signal_sanitizer_strips_query_and_fragment_values()
    {
        var sanitized = SiteSafetyObservedSignalSanitizer.Sanitize(new SiteSafetyObservedSignals(
            RedirectChain: ["https://example.com/redirect?token=secret#frag"],
            ExternalScriptUrls: ["https://cdn.example.com/app.js?session=abc"],
            DownloadLinks: ["https://files.example.com/tool.exe?downloadToken=secret"],
            MatchedRiskTerms: ["CrackedSoftware"]));

        Assert.Multiple(() =>
        {
            Assert.That(sanitized.RedirectChain!.Single(), Is.EqualTo("https://example.com/redirect"));
            Assert.That(sanitized.ExternalScriptUrls!.Single(), Is.EqualTo("https://cdn.example.com/app.js"));
            Assert.That(sanitized.DownloadLinks!.Single(), Is.EqualTo("https://files.example.com/tool.exe"));
            Assert.That(sanitized.MatchedRiskTerms!.Single(), Is.EqualTo("CrackedSoftware"));
        });
    }

    /// <summary>
    /// Verifies observed signal URLs cannot point at localhost or private-network targets.
    /// </summary>
    [Test]
    public void Site_safety_validator_rejects_internal_observed_signal_urls()
    {
        var validator = new SiteSafetyScanValidator();
        var result = validator.Validate(new SiteSafetyScanRequest(
            "https://example.com",
            new SiteSafetyObservedSignals(
                RedirectChain: ["http://localhost/admin"],
                ExternalScriptUrls: ["http://192.168.1.10/script.js"],
                DownloadLinks: ["http://10.0.0.5/file.exe"])));

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors.Select(error => error.ErrorMessage), Has.Some.Contains("Observed redirect URLs must be public HTTP or HTTPS URLs."));
    }

    /// <summary>
    /// Verifies third-party provider base classes do not call a specific scanner when that provider is disabled.
    /// </summary>
    [Test]
    public async Task Provider_without_specific_enable_switch_makes_no_external_call()
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
    /// Verifies provider cache expiry uses the injected clock so tests and future workers do not depend on real time.
    /// </summary>
    [Test]
    public void External_evidence_cache_uses_injected_clock_for_expiry()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 06, 21, 10, 13, 00, TimeSpan.Zero));
        var cache = new InMemoryExternalSiteEvidenceCache(clock);
        var evidence = SslLabsEvidence("A", SiteSafetyEvidenceStatus.Positive, risk: 0, trust: 5) with
        {
            CheckedAtUtc = clock.GetUtcNow(),
            ExpiresAtUtc = clock.GetUtcNow().AddMinutes(5)
        };

        cache.Store(evidence);

        var fresh = cache.GetFresh(evidence.ProviderName, evidence.Domain, evidence.UrlHash);
        clock.Advance(TimeSpan.FromMinutes(6));
        var expired = cache.GetFresh(evidence.ProviderName, evidence.Domain, evidence.UrlHash);

        Assert.Multiple(() =>
        {
            Assert.That(fresh, Is.Not.Null);
            Assert.That(expired, Is.Null);
        });
    }

    /// <summary>
    /// Verifies provider circuit breakers reopen after the configured break window without sleeping in tests.
    /// </summary>
    [Test]
    public async Task External_provider_circuit_uses_injected_clock_for_recovery()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 06, 21, 10, 13, 00, TimeSpan.Zero));
        var policy = new InMemoryExternalProviderResiliencePolicy(clock);
        var failures = 0;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                await policy.ExecuteAsync<int>("TestProvider", _ =>
                {
                    failures++;
                    throw new InvalidOperationException("Simulated provider failure.");
                }, CancellationToken.None);
            }
            catch (InvalidOperationException)
            {
            }
        }

        Assert.ThrowsAsync<ExternalProviderCircuitOpenException>(() =>
            policy.ExecuteAsync("TestProvider", _ => Task.FromResult(1), CancellationToken.None));

        clock.Advance(TimeSpan.FromMinutes(2));
        var recovered = await policy.ExecuteAsync("TestProvider", _ => Task.FromResult(42), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(failures, Is.EqualTo(3));
            Assert.That(recovered, Is.EqualTo(42));
        });
    }

    /// <summary>
    /// Verifies concrete providers follow the MVP default: SSL Labs is live, credentialed providers remain disabled.
    /// </summary>
    [Test]
    public async Task Concrete_external_providers_enable_ssl_labs_by_default_only()
    {
        var options = new ExternalSiteEvidenceOptions();
        var cache = new InMemoryExternalSiteEvidenceCache();
        var handler = new StubHttpMessageHandler(_ => JsonResponse("""{"status":"READY","endpoints":[{"grade":"A"}]}"""));
        ISiteSafetyEvidenceProvider[] providers =
        [
            new SslLabsSiteEvidenceProvider(cache, options, TestResiliencePolicy(), new HttpClient(handler)),
            new GoogleWebRiskSiteEvidenceProvider(cache, options, TestResiliencePolicy()),
            new VirusTotalSiteEvidenceProvider(cache, options, TestResiliencePolicy())
        ];

        var evidence = new List<SiteSafetyEvidence>();
        foreach (var provider in providers)
        {
            evidence.Add(await provider.CollectEvidenceAsync(Context(), CancellationToken.None));
        }

        Assert.Multiple(() =>
        {
            Assert.That(evidence.Select(item => item.ProviderName), Does.Contain("SSL Labs / Qualys TLS"));
            Assert.That(evidence.Select(item => item.ProviderName), Does.Contain("Google Web Risk / Safe Browsing"));
            Assert.That(evidence.Select(item => item.ProviderName), Does.Contain("VirusTotal"));
            Assert.That(handler.RequestUris, Has.Count.EqualTo(1));
            Assert.That(evidence.Single(item => item.ProviderName == "SSL Labs / Qualys TLS").EvidenceItems.Single().Value, Is.EqualTo("A"));
            Assert.That(evidence.Where(item => item.ProviderName != "SSL Labs / Qualys TLS").SelectMany(item => item.Errors), Has.All.Contains("disabled"));
        });
    }

    /// <summary>
    /// Verifies the slow-path collector can run external providers even when request-path scans skip them.
    /// </summary>
    [Test]
    public async Task External_collector_runs_external_providers_off_request_path()
    {
        var options = new ExternalSiteEvidenceOptions
        {
            ExternalProvidersEnabled = true,
            RunExternalProvidersOnRequestPath = false
        };
        var providerOptions = new ExternalProviderOptions { Enabled = true };
        var provider = new TestExternalProvider(new InMemoryExternalSiteEvidenceCache(), options, providerOptions);
        var collector = CreateExternalCollector(provider);

        var evidence = await collector.CollectAsync(new SiteSafetyScanRequest("https://example.com/login?token=secret"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(provider.ExternalCallCount, Is.EqualTo(1));
            Assert.That(evidence.Single().ProviderName, Is.EqualTo("TestExternalProvider"));
            Assert.That(evidence.Single().Domain, Is.EqualTo("example.com"));
            Assert.That(evidence.Single().ToString(), Does.Not.Contain("token=secret"));
        });
    }

    /// <summary>
    /// Verifies the external collector returns safe error evidence when a provider fails.
    /// </summary>
    [Test]
    public async Task External_collector_returns_safe_error_evidence_when_provider_fails()
    {
        var collector = CreateExternalCollector(new ThrowingExternalProvider());

        var evidence = await collector.CollectAsync(new SiteSafetyScanRequest("https://example.com/private?password=secret"), CancellationToken.None);

        var failure = evidence.Single();
        Assert.Multiple(() =>
        {
            Assert.That(failure.ProviderName, Is.EqualTo("ThrowingExternalProvider"));
            Assert.That(failure.Errors, Has.Some.EqualTo("Provider failed safely."));
            Assert.That(failure.IsAuthoritativeForRisk, Is.False);
            Assert.That(failure.IsAuthoritativeForTrust, Is.False);
            Assert.That(failure.ToString(), Does.Not.Contain("password=secret"));
        });
    }

    /// <summary>
    /// Verifies the external collector rejects private scan targets before any external provider can receive them.
    /// </summary>
    [Test]
    public void External_collector_rejects_private_targets_before_provider_call()
    {
        var providerOptions = new ExternalProviderOptions { Enabled = true };
        var provider = new TestExternalProvider(
            new InMemoryExternalSiteEvidenceCache(),
            new ExternalSiteEvidenceOptions { ExternalProvidersEnabled = true },
            providerOptions);
        var collector = CreateExternalCollector(provider);

        Assert.ThrowsAsync<FluentValidation.ValidationException>(() =>
            collector.CollectAsync(new SiteSafetyScanRequest("http://localhost/admin"), CancellationToken.None));
        Assert.That(provider.ExternalCallCount, Is.EqualTo(0));
    }

    /// <summary>
    /// Verifies a provider-specific disabled switch prevents external collection even when the global switch is on.
    /// </summary>
    [Test]
    public async Task Disabled_provider_makes_no_external_call()
    {
        var options = new ExternalSiteEvidenceOptions { ExternalProvidersEnabled = true };
        var providerOptions = new ExternalProviderOptions { Enabled = false };
        var provider = new TestExternalProvider(new InMemoryExternalSiteEvidenceCache(), options, providerOptions);

        var evidence = await provider.CollectEvidenceAsync(Context(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(provider.ExternalCallCount, Is.EqualTo(0));
            Assert.That(evidence.Errors, Has.Some.Contains("disabled by provider configuration"));
            Assert.That(evidence.IsAuthoritativeForRisk, Is.False);
            Assert.That(evidence.IsAuthoritativeForTrust, Is.False);
        });
    }

    /// <summary>
    /// Verifies enabled placeholder providers fail safely when API credentials or adapters are missing.
    /// </summary>
    [Test]
    public async Task Missing_api_key_fails_safely_without_score_impact()
    {
        var options = new ExternalSiteEvidenceOptions
        {
            ExternalProvidersEnabled = true,
            GoogleWebRisk = new ExternalProviderOptions { Enabled = true }
        };
        var provider = new GoogleWebRiskSiteEvidenceProvider(new InMemoryExternalSiteEvidenceCache(), options, TestResiliencePolicy());

        var evidence = await provider.CollectEvidenceAsync(Context(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(evidence.Errors, Has.Some.Contains("API credentials"));
            Assert.That(evidence.EvidenceItems, Is.Empty);
            Assert.That(evidence.Confidence, Is.EqualTo(0));
            Assert.That(evidence.IsAuthoritativeForRisk, Is.False);
            Assert.That(evidence.IsAuthoritativeForTrust, Is.False);
        });
    }

    /// <summary>
    /// Verifies provider-specific enablement does not leak private content when a concrete adapter is not configured.
    /// </summary>
    [Test]
    public async Task Enabled_ssl_labs_provider_uses_safe_failure_when_provider_is_unavailable()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.BadGateway));
        var options = new ExternalSiteEvidenceOptions
        {
            ExternalProvidersEnabled = true,
            SslLabs = new ExternalProviderOptions { Enabled = true }
        };
        var provider = new SslLabsSiteEvidenceProvider(new InMemoryExternalSiteEvidenceCache(), options, TestResiliencePolicy(), new HttpClient(handler));

        var evidence = await provider.CollectEvidenceAsync(Context("https://example.com/login?password=secret"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(evidence.Errors, Has.Some.Contains("SSL Labs TLS check returned HTTP 502."));
            Assert.That(evidence.EvidenceItems, Is.Empty);
            Assert.That(evidence.ToString(), Does.Not.Contain("password=secret"));
            Assert.That(evidence.ToString(), Does.Not.Contain("page body"));
            Assert.That(evidence.ToString(), Does.Not.Contain("form values"));
            Assert.That(evidence.ToString(), Does.Not.Contain("email content"));
        });
    }

    /// <summary>
    /// Verifies the real SSL Labs adapter sends only the domain, not the full page URL or private query values.
    /// </summary>
    [Test]
    public async Task Ssl_labs_provider_calls_domain_only_endpoint_when_enabled()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse("""{"status":"READY","endpoints":[{"grade":"A"}]}"""));
        var provider = new SslLabsSiteEvidenceProvider(
            new InMemoryExternalSiteEvidenceCache(),
            EnabledSslLabsOptions(),
            TestResiliencePolicy(),
            new HttpClient(handler));

        var evidence = await provider.CollectEvidenceAsync(Context("https://example.com/login?password=secret"), CancellationToken.None);

        var requestUri = handler.RequestUris.Single()!.ToString();
        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(requestUri, Does.Contain("host=example.com"));
            Assert.That(requestUri, Does.Contain("startNew=off"));
            Assert.That(requestUri, Does.Not.Contain("startNew=on"));
            Assert.That(requestUri, Does.Not.Contain("login"));
            Assert.That(requestUri, Does.Not.Contain("password=secret"));
            Assert.That(item.Category, Is.EqualTo("TlsGrade"));
            Assert.That(item.Value, Is.EqualTo("A"));
            Assert.That(item.TrustImpact, Is.EqualTo(5));
            Assert.That(item.RiskImpact, Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Verifies weak SSL Labs grades create cautionary evidence instead of a trust signal.
    /// </summary>
    [Test]
    public async Task Ssl_labs_provider_weak_grade_lowers_confidence()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse("""{"status":"READY","endpoints":[{"grade":"F"}]}"""));
        var provider = new SslLabsSiteEvidenceProvider(
            new InMemoryExternalSiteEvidenceCache(),
            EnabledSslLabsOptions(),
            TestResiliencePolicy(),
            new HttpClient(handler));

        var evidence = await provider.CollectEvidenceAsync(Context(), CancellationToken.None);

        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(item.Value, Is.EqualTo("F"));
            Assert.That(item.Status, Is.EqualTo(SiteSafetyEvidenceStatus.Weak));
            Assert.That(item.RiskImpact, Is.EqualTo(25));
            Assert.That(item.TrustImpact, Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Verifies pending SSL Labs scans do not create a fake trust boost.
    /// </summary>
    [Test]
    public async Task Ssl_labs_provider_pending_assessment_does_not_add_trust()
    {
        var handler = new StubHttpMessageHandler(_ => JsonResponse("""{"status":"IN_PROGRESS"}"""));
        var provider = new SslLabsSiteEvidenceProvider(
            new InMemoryExternalSiteEvidenceCache(),
            EnabledSslLabsOptions(),
            TestResiliencePolicy(),
            new HttpClient(handler));

        var evidence = await provider.CollectEvidenceAsync(Context(), CancellationToken.None);

        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(item.Category, Is.EqualTo("TlsAssessmentStatus"));
            Assert.That(item.Summary, Does.Contain("IN_PROGRESS"));
            Assert.That(item.TrustImpact, Is.EqualTo(0));
            Assert.That(evidence.IsAuthoritativeForTrust, Is.False);
            Assert.That(evidence.Errors, Is.Empty);
        });
    }

    /// <summary>
    /// Verifies SSL Labs failures are represented as safe evidence errors and do not leak private URL data.
    /// </summary>
    [Test]
    public async Task Ssl_labs_provider_http_failure_returns_safe_error()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var provider = new SslLabsSiteEvidenceProvider(
            new InMemoryExternalSiteEvidenceCache(),
            EnabledSslLabsOptions(),
            TestResiliencePolicy(),
            new HttpClient(handler));

        var evidence = await provider.CollectEvidenceAsync(Context("https://example.com/private?token=secret"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(evidence.Errors, Has.Some.Contains("HTTP 500"));
            Assert.That(evidence.EvidenceItems, Is.Empty);
            Assert.That(evidence.ToString(), Does.Not.Contain("token=secret"));
            Assert.That(evidence.IsAuthoritativeForRisk, Is.False);
        });
    }

    /// <summary>
    /// Verifies SSL Labs-style normalized TLS grades only create a small trust signal.
    /// </summary>
    [Test]
    public void Ssl_labs_provider_normalizes_tls_grade_as_small_trust_signal()
    {
        var provider = new SslLabsSiteEvidenceProvider(new InMemoryExternalSiteEvidenceCache(), new ExternalSiteEvidenceOptions(), TestResiliencePolicy());

        var evidence = provider.CreateTlsGradeEvidence(Context(), "A", "TLS scanner reported strong TLS configuration.");

        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(item.Category, Is.EqualTo("TlsGrade"));
            Assert.That(item.EvidenceType, Is.EqualTo("TlsGrade"));
            Assert.That(item.Status, Is.EqualTo(SiteSafetyEvidenceStatus.Positive));
            Assert.That(item.TrustImpact, Is.EqualTo(5));
            Assert.That(item.Confidence, Is.EqualTo(80));
            Assert.That(item.IsPositiveSignal, Is.True);
            Assert.That(item.IsNegativeSignal, Is.False);
            Assert.That(item.IsBlockingSignal, Is.False);
            Assert.That(evidence.IsAuthoritativeForTrust, Is.True);
            Assert.That(evidence.IsAuthoritativeForRisk, Is.False);
        });
    }

    /// <summary>
    /// Verifies Google Web Risk-style threat matches normalize to authoritative risk evidence.
    /// </summary>
    [Test]
    public void Google_web_risk_provider_normalizes_phishing_match()
    {
        var provider = new GoogleWebRiskSiteEvidenceProvider(new InMemoryExternalSiteEvidenceCache(), new ExternalSiteEvidenceOptions(), TestResiliencePolicy());

        var evidence = provider.CreateThreatMatchEvidence(Context(), "SOCIAL_ENGINEERING");

        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(item.Category, Is.EqualTo("PhishingMatch"));
            Assert.That(item.EvidenceType, Is.EqualTo("ThreatMatch"));
            Assert.That(item.Status, Is.EqualTo(SiteSafetyEvidenceStatus.Dangerous));
            Assert.That(item.RiskImpact, Is.EqualTo(95));
            Assert.That(item.Severity, Is.EqualTo(SiteSafetyEvidenceSeverity.Critical));
            Assert.That(item.EvidenceQuality, Is.EqualTo(SiteSafetyEvidenceItemQuality.Strong));
            Assert.That(item.IsNegativeSignal, Is.True);
            Assert.That(item.IsBlockingSignal, Is.True);
            Assert.That(evidence.IsAuthoritativeForRisk, Is.True);
            Assert.That(evidence.IsAuthoritativeForTrust, Is.False);
        });
    }

    /// <summary>
    /// Verifies VirusTotal-style malware matches normalize to authoritative risk evidence.
    /// </summary>
    [Test]
    public void VirusTotal_provider_normalizes_malware_match()
    {
        var provider = new VirusTotalSiteEvidenceProvider(new InMemoryExternalSiteEvidenceCache(), new ExternalSiteEvidenceOptions(), TestResiliencePolicy());

        var evidence = provider.CreateMalwareMatchEvidence(Context(), "malicious");

        var item = evidence.EvidenceItems.Single();
        Assert.Multiple(() =>
        {
            Assert.That(item.Category, Is.EqualTo("MalwareMatch"));
            Assert.That(item.EvidenceType, Is.EqualTo("ThreatMatch"));
            Assert.That(item.Status, Is.EqualTo(SiteSafetyEvidenceStatus.Dangerous));
            Assert.That(item.RiskImpact, Is.EqualTo(95));
            Assert.That(item.IsNegativeSignal, Is.True);
            Assert.That(item.IsBlockingSignal, Is.True);
            Assert.That(evidence.IsAuthoritativeForRisk, Is.True);
            Assert.That(evidence.IsAuthoritativeForTrust, Is.False);
        });
    }

    /// <summary>
    /// Verifies browser-observed evidence marks risky signals without storing raw page content.
    /// </summary>
    [Test]
    public async Task Browser_observed_provider_marks_negative_and_blocking_signals()
    {
        var provider = new BrowserObservedSignalProvider();
        var context = Context() with
        {
            ObservedSignals = new SiteSafetyObservedSignals(
                DownloadLinks: ["https://example.com/setup.exe"],
                KnownPhishingPattern: true)
        };

        var evidence = await provider.CollectEvidenceAsync(context, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(evidence.EvidenceItems, Has.Some.Matches<SiteSafetyEvidenceItem>(item => item.IsNegativeSignal));
            Assert.That(evidence.EvidenceItems, Has.Some.Matches<SiteSafetyEvidenceItem>(item => item.IsBlockingSignal));
            Assert.That(evidence.ToString(), Does.Not.Contain("page text"));
            Assert.That(evidence.ToString(), Does.Not.Contain("form value"));
        });
    }

    /// <summary>
    /// Verifies clean browser evidence still explains what privacy-safe checks ran.
    /// </summary>
    [Test]
    public async Task Browser_observed_provider_returns_clean_check_details_when_no_risk_is_seen()
    {
        var provider = new BrowserObservedSignalProvider();
        var context = Context() with
        {
            ObservedSignals = new SiteSafetyObservedSignals(
                ExternalScriptUrls: ["https://cdn.example.com/app.js"],
                InlineScriptCount: 2,
                DownloadLinks: ["https://example.com/file.txt"])
        };

        var evidence = await provider.CollectEvidenceAsync(context, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(evidence.EvidenceItems, Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("BrowserObserved"));
            Assert.That(evidence.EvidenceItems, Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("LinksChecked"));
            Assert.That(evidence.EvidenceItems, Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("FormsChecked"));
            Assert.That(evidence.EvidenceItems, Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("DownloadsChecked"));
            Assert.That(evidence.EvidenceItems, Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("ScriptsChecked"));
            Assert.That(evidence.EvidenceItems.Select(item => item.Summary), Has.Some.Contains("No obvious malware or phishing signals were observed."));
            Assert.That(evidence.ToString(), Does.Not.Contain("form value"));
        });
    }

    /// <summary>
    /// Creates a scanner with production validation and test evidence providers.
    /// </summary>
    private static SiteSafetyScanner CreateScanner(params ISiteSafetyEvidenceProvider[] providers) =>
        new(new SiteSafetyScanValidator(), NullLogger<SiteSafetyScanner>.Instance, providers);

    /// <summary>
    /// Creates an external collector with production validation and test evidence providers.
    /// </summary>
    private static ExternalSiteEvidenceCollector CreateExternalCollector(params ISiteSafetyEvidenceProvider[] providers) =>
        new(new SiteSafetyScanValidator(), providers, NullLogger<ExternalSiteEvidenceCollector>.Instance);

    /// <summary>
    /// Creates a privacy-safe provider context for direct provider tests.
    /// </summary>
    private static SiteSafetyEvidenceContext Context(string url = "https://example.com") =>
        new(new Uri(url), "example.com", "hash", new SiteSafetyObservedSignals(), DateTimeOffset.UtcNow);

    /// <summary>
    /// Creates options that explicitly enable the SSL Labs adapter for tests.
    /// </summary>
    private static ExternalSiteEvidenceOptions EnabledSslLabsOptions() =>
        new()
        {
            ExternalProvidersEnabled = true,
            SslLabs = new ExternalProviderOptions
            {
                Enabled = true,
                Endpoint = "https://api.ssllabs.com/api/v3/analyze"
            }
        };

    /// <summary>
    /// Creates a JSON HTTP response for fake provider responses.
    /// </summary>
    private static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json)
        };

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
    /// Creates the explicit test resilience policy required by external providers after runtime in-memory fallbacks were removed.
    /// </summary>
    /// <returns>A deterministic in-memory policy used only inside provider unit tests.</returns>
    private static InMemoryExternalProviderResiliencePolicy TestResiliencePolicy() => new();

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
    private sealed class TestExternalProvider(
        IExternalSiteEvidenceCache cache,
        ExternalSiteEvidenceOptions options,
        ExternalProviderOptions? providerOptions = null)
        : ExternalSiteEvidenceProviderBase(cache, options, TestResiliencePolicy())
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
        protected override ExternalProviderOptions ProviderOptions => providerOptions ?? new ExternalProviderOptions();

        /// <inheritdoc />
        protected override Task<SiteSafetyEvidence> CollectExternalEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
        {
            ExternalCallCount++;
            return Task.FromResult(ThreatIntelEvidence("PhishingMatch", SiteSafetyEvidenceStatus.Dangerous, 95) with
            {
                ProviderName = ProviderName,
                Domain = context.Domain,
                UrlHash = context.UrlHash
            });
        }
    }

    /// <summary>
    /// Test external provider that simulates an unexpected provider failure.
    /// </summary>
    private sealed class ThrowingExternalProvider : IExternalSiteEvidenceProvider
    {
        /// <inheritdoc />
        public string ProviderName => "ThrowingExternalProvider";

        /// <inheritdoc />
        public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.ThreatIntel;

        /// <inheritdoc />
        public ExternalSiteEvidenceOptions CurrentOptions => new();

        /// <inheritdoc />
        public Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Simulated provider failure.");
    }

    /// <summary>
    /// HTTP handler used to test provider requests without calling external networks.
    /// </summary>
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        /// <summary>
        /// Gets the request URIs received by the stub.
        /// </summary>
        public List<Uri?> RequestUris { get; } = [];

        /// <inheritdoc />
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri);
            return Task.FromResult(responseFactory(request));
        }
    }

    /// <summary>
    /// Simple test clock for provider cache and resilience tests.
    /// </summary>
    private sealed class ManualTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        private DateTimeOffset currentUtc = initialUtc;

        /// <summary>
        /// Gets the current fake UTC time.
        /// </summary>
        /// <returns>The current fake UTC time.</returns>
        public override DateTimeOffset GetUtcNow() => currentUtc;

        /// <summary>
        /// Moves the fake clock forward.
        /// </summary>
        /// <param name="duration">How far to advance the fake clock.</param>
        public void Advance(TimeSpan duration) => currentUtc = currentUtc.Add(duration);
    }
}
