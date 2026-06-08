using HIP.Application.Browser;
using HIP.Application.Reporting;
using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using NUnit.Framework;

namespace HIP.Tests.Scalability;

/// <summary>
/// Verifies HIP's scalability extension points keep the scan hot path privacy-safe and replaceable.
/// </summary>
[TestFixture]
public sealed class ScalabilityFoundationTests
{
    /// <summary>
    /// Verifies latest scan results are cached for hot-path lookup after persistence.
    /// </summary>
    [Test]
    public async Task Scan_result_cache_is_updated_when_scan_is_saved()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var cache = new InMemoryScanResultCache();
        var aggregate = new InMemoryDashboardScanAggregateStore();
        var service = new BrowserScanResultService(repository, new Sha256PrivacyHashingService(), cache, aggregate);

        await service.SaveAsync(ValidRequest(), CancellationToken.None);
        var cached = await cache.GetFreshAsync("example.com", CancellationToken.None);

        Assert.That(cached?.Result.Domain, Is.EqualTo("example.com"));
    }

    /// <summary>
    /// Verifies expired hot-path cache entries are ignored so stale scores do not persist forever.
    /// </summary>
    [Test]
    public async Task Scan_result_cache_returns_empty_state_after_expiry()
    {
        var cache = new InMemoryScanResultCache();
        await cache.StoreAsync(StoredResult("example.com", "LimitedTrustData"), TimeSpan.FromMilliseconds(-1), CancellationToken.None);

        var cached = await cache.GetFreshAsync("example.com", CancellationToken.None);

        Assert.That(cached, Is.Null);
    }

    /// <summary>
    /// Verifies dedupe keys combine domain, URL hash, and signal hash.
    /// </summary>
    [Test]
    public async Task Dedupe_rejects_repeated_domain_url_hash_and_signal_hash()
    {
        var dedupe = new InMemoryScanResultDedupeService();
        var key = new ScanDedupeKey("example.com", "sha256:" + new string('a', 64), "sha256:" + new string('b', 64));

        var first = await dedupe.TryAcceptAsync(key, TimeSpan.FromMinutes(5), CancellationToken.None);
        var second = await dedupe.TryAcceptAsync(key, TimeSpan.FromMinutes(5), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(true));
            Assert.That(second, Is.EqualTo(false));
        });
    }

    /// <summary>
    /// Verifies the queue accepts privacy-safe slow-path requests without raw page data.
    /// </summary>
    [Test]
    public async Task Queue_request_can_be_created_for_slow_path_provider_work()
    {
        var queue = new InMemoryScanIngestionQueue();
        var request = new ScanIngestionRequest(
            "scan:1",
            "example.com",
            "sha256:" + new string('c', 64),
            "sha256:" + new string('d', 64),
            "BrowserPlugin",
            "0.1.0-dev",
            DateTimeOffset.UtcNow,
            ScanProcessingPath.SlowPath);

        await queue.EnqueueAsync(request, CancellationToken.None);
        var batch = await queue.DequeueBatchAsync(10, CancellationToken.None);

        Assert.That(batch.Single(), Is.EqualTo(request));
    }

    /// <summary>
    /// Verifies provider evidence cache respects expiry so external scanner results can be reused safely.
    /// </summary>
    [Test]
    public void Provider_evidence_cache_uses_expiry()
    {
        var cache = new InMemoryExternalSiteEvidenceCache();
        var expiredEvidence = new SiteSafetyEvidence(
            "SSL Labs / Qualys TLS",
            SiteSafetyEvidenceProviderType.TlsScanner,
            SiteSafetyEvidenceTargetType.Domain,
            "example.com",
            "sha256:" + new string('e', 64),
            [],
            80,
            DateTimeOffset.UtcNow.AddHours(-2),
            DateTimeOffset.UtcNow.AddMinutes(-1),
            [],
            false,
            true);

        cache.Store(expiredEvidence);
        var fresh = cache.GetFresh(expiredEvidence.ProviderName, expiredEvidence.Domain, expiredEvidence.UrlHash);

        Assert.That(fresh, Is.Null);
    }

    /// <summary>
    /// Verifies dashboard aggregates update as stored scans arrive.
    /// </summary>
    [Test]
    public async Task Dashboard_aggregate_updates_from_scan_results()
    {
        var aggregateStore = new InMemoryDashboardScanAggregateStore();

        await aggregateStore.UpdateAsync(StoredResult("trusted.example", "Trusted"), CancellationToken.None);
        await aggregateStore.UpdateAsync(StoredResult("danger.example", "Dangerous"), CancellationToken.None);
        var aggregate = await aggregateStore.GetAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(aggregate.TotalScans, Is.EqualTo(2));
            Assert.That(aggregate.Trusted, Is.EqualTo(1));
            Assert.That(aggregate.Dangerous, Is.EqualTo(1));
        });
    }

    /// <summary>
    /// Verifies an empty aggregate makes no-data dashboard state explicit.
    /// </summary>
    [Test]
    public async Task Dashboard_aggregate_has_empty_state_before_scans()
    {
        var aggregate = await new InMemoryDashboardScanAggregateStore().GetAsync(CancellationToken.None);

        Assert.That(aggregate.TotalScans, Is.EqualTo(0));
    }

    /// <summary>
    /// Verifies the MVP rate limiter is explicit about being a development placeholder.
    /// </summary>
    [Test]
    public async Task Rate_limit_placeholder_allows_but_marks_development_behavior()
    {
        var limiter = new DevelopmentSubmissionRateLimiter();

        var decision = await limiter.CheckAsync("browser-plugin:example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(decision.Allowed, Is.EqualTo(true));
            Assert.That(decision.Reason, Does.Contain("Development placeholder"));
        });
    }

    /// <summary>
    /// Verifies the service stores signal hashes and rejects private metadata fields.
    /// </summary>
    [Test]
    public async Task Stored_scan_contains_signal_hash_without_private_page_data()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var service = new BrowserScanResultService(repository, new Sha256PrivacyHashingService());

        await service.SaveAsync(ValidRequest(), CancellationToken.None);
        var stored = await repository.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stored!.PrivacySafeMetadata["signalHash"], Does.StartWith("sha256:"));
            Assert.That(stored.PrivacySafeMetadata.Keys, Does.Not.Contain("pageText"));
            Assert.That(stored.PrivacySafeMetadata.Keys, Does.Not.Contain("formValues"));
            Assert.That(stored.StoredPageUrl, Is.Null);
        });
    }

    /// <summary>
    /// Verifies scanner submissions with private fields are still rejected at the service boundary.
    /// </summary>
    [Test]
    public void Privacy_unsafe_scan_metadata_is_rejected()
    {
        var service = new BrowserScanResultService(new InMemoryBrowserScanResultRepository(), new Sha256PrivacyHashingService());

        Assert.ThrowsAsync<ArgumentException>(() =>
            service.SaveAsync(ValidRequest() with
            {
                PrivacySafeMetadata = new Dictionary<string, string>
                {
                    ["password"] = "secret"
                }
            }, CancellationToken.None));
    }

    /// <summary>
    /// Creates a valid browser scan result save request.
    /// </summary>
    /// <returns>Valid save request.</returns>
    private static BrowserScanResultSaveRequest ValidRequest() =>
        new(
            "example.com",
            "https://example.com/path?token=not-stored",
            56,
            "LimitedTrustData",
            "LimitedTrustData",
            ["HIP has limited public trust data for this site."],
            4,
            0,
            0,
            0,
            "ShowCaution",
            new Dictionary<string, string>
            {
                ["pluginVersion"] = "0.1.0-dev",
                ["downloadCandidates"] = "0"
            });

    /// <summary>
    /// Creates a stored scan result for cache and aggregate tests.
    /// </summary>
    /// <param name="domain">Domain to store.</param>
    /// <param name="status">Status label.</param>
    /// <returns>Stored browser scan record.</returns>
    private static BrowserScanResultRecord StoredResult(string domain, string status) =>
        new(
            $"browser-scan:{domain}:test",
            domain,
            "sha256:" + new string('f', 64),
            null,
            "BrowserPlugin",
            status == "Dangerous" ? 8 : 88,
            status,
            status,
            ["Privacy-safe stored scan summary."],
            5,
            status == "Dangerous" ? 1 : 0,
            status == "Dangerous" ? 1 : 0,
            status == "Dangerous" ? 1 : 0,
            DateTimeOffset.UtcNow,
            status == "Dangerous" ? "Block" : "Allow",
            new Dictionary<string, string>
            {
                ["signalHash"] = "sha256:" + new string('1', 64)
            });
}
