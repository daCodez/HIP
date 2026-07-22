using HIP.Application.Browser;
using HIP.Application.Reporting;
using HIP.Application.Scalability;
using NUnit.Framework;
using System.Text.Json;

namespace HIP.Tests.Browser;

/// <summary>
/// Tests the browser scan result service privacy boundary and validation rules.
/// </summary>
[TestFixture]
public sealed class BrowserScanResultServiceTests
{
    /// <summary>
    /// Verifies a valid browser plugin result can be saved and read back by domain.
    /// </summary>
    [Test]
    public async Task Browser_scan_result_can_be_saved_and_retrieved_by_domain()
    {
        var service = CreateService();

        await service.SaveAsync(ValidRequest(), CancellationToken.None);
        var result = await service.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Domain, Is.EqualTo("example.com"));
    }

    /// <summary>
    /// Verifies saved results retain score, status, and plain-English reasons.
    /// </summary>
    [Test]
    public async Task Saved_result_includes_score_status_and_reasons()
    {
        var service = CreateService();

        await service.SaveAsync(ValidRequest(), CancellationToken.None);
        var result = await service.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result!.Score, Is.EqualTo(84));
            Assert.That(result.Status, Is.EqualTo("Trusted"));
            Assert.That(result.Reasons, Does.Contain("No risky links found"));
        });
    }

    /// <summary>
    /// Verifies saved results retain page scan counters needed by the browser popup and future dashboards.
    /// </summary>
    [Test]
    public async Task Saved_result_includes_scan_counts()
    {
        var service = CreateService();

        await service.SaveAsync(ValidRequest() with
        {
            LinksScanned = 42,
            RiskyLinksFound = 2,
            SuspiciousLinksFound = 2,
            DangerousLinksFound = 0
        }, CancellationToken.None);
        var result = await service.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result!.LinksScanned, Is.EqualTo(42));
            Assert.That(result.RiskyLinksFound, Is.EqualTo(2));
            Assert.That(result.SuspiciousLinksFound, Is.EqualTo(2));
            Assert.That(result.DangerousLinksFound, Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Verifies the stored record hashes page URLs and does not retain the raw URL by default.
    /// </summary>
    [Test]
    public async Task Page_url_is_hashed_and_raw_url_is_not_stored()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var service = new BrowserScanResultService(repository, new Sha256PrivacyHashingService(), new InMemoryScanResultCache(), new InMemoryDashboardScanAggregateStore());

        await service.SaveAsync(ValidRequest(), CancellationToken.None);
        var stored = await repository.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stored!.PageUrlHash, Does.StartWith("sha256:"));
            Assert.That(stored.PageUrlHash, Is.Not.EqualTo("https://example.com/account?token=secret"));
            Assert.That(stored.StoredPageUrl, Is.Null);
        });
    }

    /// <summary>
    /// Verifies the API-facing scan models do not include page text or form content storage fields.
    /// </summary>
    [Test]
    public void Browser_scan_result_models_do_not_store_page_text_or_form_contents()
    {
        var requestProperties = typeof(BrowserScanResultSaveRequest).GetProperties().Select(property => property.Name).ToArray();
        var recordProperties = typeof(BrowserScanResultRecord).GetProperties().Select(property => property.Name).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(requestProperties, Does.Not.Contain("PageText"));
            Assert.That(requestProperties, Does.Not.Contain("FormContents"));
            Assert.That(requestProperties, Does.Not.Contain("PrivateContent"));
            Assert.That(recordProperties, Does.Not.Contain("PageText"));
            Assert.That(recordProperties, Does.Not.Contain("FormContents"));
            Assert.That(recordProperties, Does.Not.Contain("PrivateContent"));
        });
    }

    /// <summary>
    /// Verifies invalid domains are rejected before any persistence occurs.
    /// </summary>
    [Test]
    public void Invalid_domain_is_rejected()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() =>
            service.SaveAsync(ValidRequest() with { Domain = "not a domain" }, CancellationToken.None));
    }

    /// <summary>
    /// Verifies invalid scores are rejected before they can affect HIP score history.
    /// </summary>
    [Test]
    public void Invalid_score_is_rejected()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() =>
            service.SaveAsync(ValidRequest() with { Score = 101 }, CancellationToken.None));
    }

    /// <summary>
    /// Verifies metadata keys associated with private content are rejected.
    /// </summary>
    [Test]
    public void Private_metadata_fields_are_rejected()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() =>
            service.SaveAsync(ValidRequest() with
            {
                PrivacySafeMetadata = new Dictionary<string, string>
                {
                    ["formContents"] = "username=alice"
                }
            }, CancellationToken.None));
    }

    /// <summary>
    /// Verifies unattested submissions remain durable telemetry without entering the shared authoritative hot cache.
    /// </summary>
    [Test]
    public async Task Untrusted_save_does_not_write_shared_scan_cache_and_exposes_provenance()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var cache = new RecordingScanResultCache();
        var service = new BrowserScanResultService(
            repository,
            new Sha256PrivacyHashingService(),
            cache,
            new InMemoryDashboardScanAggregateStore());

        await ((IUntrustedBrowserScanResultSubmissionService)service).SaveUntrustedAsync(
            ValidRequest(),
            CancellationToken.None);

        var stored = await repository.GetLatestByDomainAsync("example.com", CancellationToken.None);
        var response = await service.GetLatestByDomainAsync("example.com", CancellationToken.None);
        var json = JsonSerializer.Serialize(response);

        Assert.Multiple(() =>
        {
            Assert.That(cache.StoreCount, Is.Zero, "Untrusted telemetry must not replace the cache consumed by authoritative/latest reads.");
            Assert.That(stored, Is.Not.Null);
            Assert.That(BrowserScanResultProvenance.IsServerAuthoritative(stored!), Is.False);
            Assert.That(json, Does.Contain("\"SubmissionTrust\":\"untrusted-client\""));
            Assert.That(json, Does.Contain("\"IsAuthoritative\":false"));
        });
    }

    /// <summary>
    /// Verifies the compatibility raw-latest query does not hide newer untrusted telemetry behind an older authoritative cache entry.
    /// </summary>
    [Test]
    public async Task Raw_latest_query_returns_newer_untrusted_record_when_authoritative_cache_exists()
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var cache = new RecordingScanResultCache();
        var service = new BrowserScanResultService(
            repository,
            new Sha256PrivacyHashingService(),
            cache,
            new InMemoryDashboardScanAggregateStore());

        await service.SaveAsync(
            ValidRequest() with { ScannedAtUtc = DateTimeOffset.UtcNow.AddHours(-1) },
            CancellationToken.None);
        await ((IUntrustedBrowserScanResultSubmissionService)service).SaveUntrustedAsync(
            ValidRequest() with
            {
                Score = 7,
                RiskLevel = "Dangerous",
                Status = "Dangerous",
                RecommendedAction = "RouteToSafetyPage"
            },
            CancellationToken.None);

        var response = await service.GetLatestByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(cache.StoreCount, Is.EqualTo(1), "Only the authoritative save should populate the shared cache.");
            Assert.That(response!.Score, Is.EqualTo(7));
            Assert.That(response.Status, Is.EqualTo("Dangerous"));
        });
    }

    /// <summary>
    /// Creates a service using in-memory persistence for isolated unit tests.
    /// </summary>
    /// <returns>A browser scan result service.</returns>
    private static BrowserScanResultService CreateService() =>
        new(
            new InMemoryBrowserScanResultRepository(),
            new Sha256PrivacyHashingService(),
            new InMemoryScanResultCache(),
            new InMemoryDashboardScanAggregateStore());

    /// <summary>
    /// Creates a valid privacy-safe request used as a baseline by tests.
    /// </summary>
    /// <returns>A valid save request.</returns>
    private static BrowserScanResultSaveRequest ValidRequest() =>
        new(
            "example.com",
            "https://example.com/account?token=secret",
            84,
            "Trusted",
            "Trusted",
            ["No risky links found"],
            12,
            0,
            0,
            0,
            "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal",
                ["downloadCandidates"] = "0"
            });

    /// <summary>
    /// Records shared hot-cache writes while retaining normal cache behavior for query regressions.
    /// </summary>
    private sealed class RecordingScanResultCache : IScanResultCache
    {
        private ScanResultCacheEntry? entry;

        /// <summary>Gets the number of cache publications.</summary>
        public int StoreCount { get; private set; }

        /// <inheritdoc />
        public Task<ScanResultCacheEntry?> GetFreshAsync(string domain, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(
                entry is not null &&
                entry.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase) &&
                entry.ExpiresAtUtc > DateTimeOffset.UtcNow
                    ? entry
                    : null);
        }

        /// <inheritdoc />
        public Task StoreAsync(BrowserScanResultRecord result, TimeSpan ttl, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StoreCount++;
            var now = DateTimeOffset.UtcNow;
            entry = new ScanResultCacheEntry(result.Domain, result, now, now.Add(ttl));
            return Task.CompletedTask;
        }
    }
}

