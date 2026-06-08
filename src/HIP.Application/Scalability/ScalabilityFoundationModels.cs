using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using HIP.Application.Browser;
using HIP.Application.SiteSafety;

namespace HIP.Application.Scalability;

/// <summary>
/// Describes whether a scan should run on the fast response path or be deferred for slower provider work.
/// </summary>
public enum ScanProcessingPath
{
    /// <summary>
    /// Returns cached or latest locally stored HIP scoring data quickly.
    /// </summary>
    HotPath,

    /// <summary>
    /// Queues deeper provider checks so external calls do not happen on every page visit.
    /// </summary>
    SlowPath
}

/// <summary>
/// Represents a privacy-safe scan ingestion request that can later be backed by a durable queue.
/// </summary>
/// <param name="RequestId">Stable request identifier assigned before enqueueing.</param>
/// <param name="Domain">Normalized domain.</param>
/// <param name="UrlHash">SHA-256 URL hash instead of a raw full URL.</param>
/// <param name="SignalHash">Hash of privacy-safe observed signals used for dedupe.</param>
/// <param name="Source">Client source such as BrowserPlugin.</param>
/// <param name="PluginVersion">Optional browser plugin version for debugging scan reliability.</param>
/// <param name="RequestedAtUtc">UTC request timestamp.</param>
/// <param name="ProcessingPath">Whether the work belongs on the hot or slow path.</param>
public sealed record ScanIngestionRequest(
    string RequestId,
    string Domain,
    string UrlHash,
    string SignalHash,
    string Source,
    string? PluginVersion,
    DateTimeOffset RequestedAtUtc,
    ScanProcessingPath ProcessingPath);

/// <summary>
/// Represents a bounded cache entry for the latest public-safe scan result for a domain.
/// </summary>
/// <param name="Domain">Normalized domain.</param>
/// <param name="Result">Privacy-safe scan summary.</param>
/// <param name="CachedAtUtc">UTC time the result was cached.</param>
/// <param name="ExpiresAtUtc">UTC time after which the cached result should not be used.</param>
public sealed record ScanResultCacheEntry(
    string Domain,
    BrowserScanResultRecord Result,
    DateTimeOffset CachedAtUtc,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Stable key used to dedupe repeated scan submissions across a short time window.
/// </summary>
/// <param name="Domain">Normalized domain.</param>
/// <param name="UrlHash">SHA-256 page URL hash.</param>
/// <param name="SignalHash">Hash of privacy-safe observed signal counts and labels.</param>
public sealed record ScanDedupeKey(string Domain, string UrlHash, string SignalHash);

/// <summary>
/// Pre-aggregated dashboard counters that can later be stored in Redis or PostgreSQL materialized views.
/// </summary>
/// <param name="TotalScans">Total stored scans observed by the aggregate.</param>
/// <param name="ScansToday">Scans received today in UTC.</param>
/// <param name="Trusted">Trusted result count.</param>
/// <param name="MostlyTrusted">MostlyTrusted result count.</param>
/// <param name="LimitedTrustData">LimitedTrustData result count.</param>
/// <param name="Unknown">Unknown result count.</param>
/// <param name="Suspicious">Suspicious result count.</param>
/// <param name="HighRisk">HighRisk result count.</param>
/// <param name="Dangerous">Dangerous result count.</param>
/// <param name="UpdatedAtUtc">UTC time the aggregate was updated.</param>
public sealed record DashboardScanAggregate(
    int TotalScans,
    int ScansToday,
    int Trusted,
    int MostlyTrusted,
    int LimitedTrustData,
    int Unknown,
    int Suspicious,
    int HighRisk,
    int Dangerous,
    DateTimeOffset UpdatedAtUtc);

/// <summary>
/// Result of a rate-limit decision for plugin/API submissions.
/// </summary>
/// <param name="Allowed">Whether the request should proceed.</param>
/// <param name="Reason">Plain-English reason safe for logs and clients.</param>
/// <param name="RetryAfter">Optional retry delay.</param>
public sealed record RateLimitDecision(bool Allowed, string Reason, TimeSpan? RetryAfter);

/// <summary>
/// Cache boundary for latest privacy-safe scan results.
/// </summary>
/// <remarks>
/// The in-memory implementation is local-dev only. Production deployments should replace this with Redis so hot-path
/// lookups do not require a full database scan on every page visit.
/// </remarks>
public interface IScanResultCache
{
    /// <summary>
    /// Gets a fresh cached scan result for a domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel cache work.</param>
    /// <returns>Fresh cache entry, or null when no fresh value exists.</returns>
    Task<ScanResultCacheEntry?> GetFreshAsync(string domain, CancellationToken cancellationToken);

    /// <summary>
    /// Stores a scan result with an expiry suitable for hot-path reads.
    /// </summary>
    /// <param name="result">Privacy-safe scan result.</param>
    /// <param name="ttl">Time to live.</param>
    /// <param name="cancellationToken">Token used to cancel cache work.</param>
    /// <returns>A task that completes when the value is cached.</returns>
    Task StoreAsync(BrowserScanResultRecord result, TimeSpan ttl, CancellationToken cancellationToken);
}

/// <summary>
/// Queue boundary for slow-path provider checks and scan enrichment work.
/// </summary>
public interface IScanIngestionQueue
{
    /// <summary>
    /// Enqueues a privacy-safe scan ingestion request.
    /// </summary>
    /// <param name="request">Request to enqueue.</param>
    /// <param name="cancellationToken">Token used to cancel queue work.</param>
    /// <returns>A task that completes when the request has been accepted.</returns>
    Task EnqueueAsync(ScanIngestionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Dequeues a bounded batch for workers.
    /// </summary>
    /// <param name="maxCount">Maximum number of items to dequeue.</param>
    /// <param name="cancellationToken">Token used to cancel queue work.</param>
    /// <returns>Dequeued requests.</returns>
    Task<IReadOnlyCollection<ScanIngestionRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken);
}

/// <summary>
/// Dedupe boundary for scan submissions, ready for Redis-backed distributed implementation.
/// </summary>
public interface IScanResultDedupeService
{
    /// <summary>
    /// Attempts to accept a scan key for a dedupe window.
    /// </summary>
    /// <param name="key">Privacy-safe dedupe key.</param>
    /// <param name="window">Window during which identical submissions are duplicates.</param>
    /// <param name="cancellationToken">Token used to cancel dedupe work.</param>
    /// <returns>True when the scan should be processed.</returns>
    Task<bool> TryAcceptAsync(ScanDedupeKey key, TimeSpan window, CancellationToken cancellationToken);
}

/// <summary>
/// Pre-aggregates dashboard counts as scan results arrive.
/// </summary>
public interface IDashboardScanAggregateStore
{
    /// <summary>
    /// Updates the aggregate with a newly stored scan result.
    /// </summary>
    /// <param name="result">Privacy-safe scan result.</param>
    /// <param name="cancellationToken">Token used to cancel aggregate work.</param>
    /// <returns>A task that completes when the aggregate is updated.</returns>
    Task UpdateAsync(BrowserScanResultRecord result, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the current aggregate snapshot.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel aggregate work.</param>
    /// <returns>Aggregate snapshot, or an empty state when no scans exist.</returns>
    Task<DashboardScanAggregate> GetAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Rate-limit boundary for plugin/API submission protection.
/// </summary>
public interface ISubmissionRateLimiter
{
    /// <summary>
    /// Checks whether a source may submit another item.
    /// </summary>
    /// <param name="sourceKey">Privacy-safe source key such as domain, API key hash, or client instance hash.</param>
    /// <param name="cancellationToken">Token used to cancel rate-limit work.</param>
    /// <returns>Rate-limit decision.</returns>
    Task<RateLimitDecision> CheckAsync(string sourceKey, CancellationToken cancellationToken);
}

/// <summary>
/// In-memory cache for local development and tests.
/// </summary>
public sealed class InMemoryScanResultCache : IScanResultCache
{
    private readonly ConcurrentDictionary<string, ScanResultCacheEntry> entries = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task<ScanResultCacheEntry?> GetFreshAsync(string domain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!entries.TryGetValue(domain, out var entry))
        {
            return Task.FromResult<ScanResultCacheEntry?>(null);
        }

        if (entry.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            entries.TryRemove(domain, out _);
            return Task.FromResult<ScanResultCacheEntry?>(null);
        }

        return Task.FromResult<ScanResultCacheEntry?>(entry);
    }

    /// <inheritdoc />
    public Task StoreAsync(BrowserScanResultRecord result, TimeSpan ttl, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        entries[result.Domain] = new ScanResultCacheEntry(result.Domain, result, now, now.Add(ttl));
        return Task.CompletedTask;
    }
}

/// <summary>
/// In-memory FIFO scan queue for local development and unit tests.
/// </summary>
public sealed class InMemoryScanIngestionQueue : IScanIngestionQueue
{
    private readonly ConcurrentQueue<ScanIngestionRequest> queue = new();

    /// <inheritdoc />
    public Task EnqueueAsync(ScanIngestionRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        queue.Enqueue(request);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<ScanIngestionRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var results = new List<ScanIngestionRequest>(Math.Max(0, maxCount));
        while (results.Count < maxCount && queue.TryDequeue(out var request))
        {
            results.Add(request);
        }

        return Task.FromResult<IReadOnlyCollection<ScanIngestionRequest>>(results);
    }
}

/// <summary>
/// In-memory dedupe store that mirrors the intended Redis SETNX-with-expiry behavior.
/// </summary>
public sealed class InMemoryScanResultDedupeService : IScanResultDedupeService
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> acceptedUntil = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> TryAcceptAsync(ScanDedupeKey key, TimeSpan window, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = DateTimeOffset.UtcNow;
        Cleanup(now);
        var fingerprint = Fingerprint(key);
        var expiresAt = now.Add(window);
        if (acceptedUntil.TryAdd(fingerprint, expiresAt))
        {
            return Task.FromResult(true);
        }

        if (acceptedUntil.TryGetValue(fingerprint, out var existing) && existing > now)
        {
            return Task.FromResult(false);
        }

        acceptedUntil[fingerprint] = expiresAt;
        return Task.FromResult(true);
    }

    /// <summary>
    /// Hashes the dedupe key so raw URL hashes and signal hashes are not used directly as dictionary keys.
    /// </summary>
    /// <param name="key">Privacy-safe dedupe key.</param>
    /// <returns>Stable dedupe fingerprint.</returns>
    private static string Fingerprint(ScanDedupeKey key)
    {
        var normalized = $"{key.Domain.Trim().ToLowerInvariant()}|{key.UrlHash.Trim().ToLowerInvariant()}|{key.SignalHash.Trim().ToLowerInvariant()}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
    }

    /// <summary>
    /// Removes expired keys to keep the local development store bounded.
    /// </summary>
    /// <param name="now">Current UTC time.</param>
    private void Cleanup(DateTimeOffset now)
    {
        foreach (var entry in acceptedUntil.Where(item => item.Value <= now).Take(100))
        {
            acceptedUntil.TryRemove(entry.Key, out _);
        }
    }
}

/// <summary>
/// In-memory pre-aggregated dashboard summary for local development and tests.
/// </summary>
public sealed class InMemoryDashboardScanAggregateStore : IDashboardScanAggregateStore
{
    private readonly object syncRoot = new();
    private DashboardScanAggregate aggregate = new(0, 0, 0, 0, 0, 0, 0, 0, 0, DateTimeOffset.MinValue);

    /// <inheritdoc />
    public Task UpdateAsync(BrowserScanResultRecord result, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (syncRoot)
        {
            var today = result.LastCheckedUtc.UtcDateTime.Date == DateTimeOffset.UtcNow.UtcDateTime.Date ? 1 : 0;
            aggregate = aggregate with
            {
                TotalScans = aggregate.TotalScans + 1,
                ScansToday = aggregate.ScansToday + today,
                Trusted = aggregate.Trusted + IsStatus(result, "Trusted"),
                MostlyTrusted = aggregate.MostlyTrusted + IsStatus(result, "MostlyTrusted", "ProbablySafe"),
                LimitedTrustData = aggregate.LimitedTrustData + IsStatus(result, "LimitedTrustData", "LimitedData"),
                Unknown = aggregate.Unknown + IsStatus(result, "Unknown"),
                Suspicious = aggregate.Suspicious + IsStatus(result, "Suspicious", "Caution"),
                HighRisk = aggregate.HighRisk + IsStatus(result, "HighRisk"),
                Dangerous = aggregate.Dangerous + IsStatus(result, "Dangerous", "Critical"),
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<DashboardScanAggregate> GetAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (syncRoot)
        {
            return Task.FromResult(aggregate);
        }
    }

    /// <summary>
    /// Converts a status match to a counter increment.
    /// </summary>
    /// <param name="result">Scan result to inspect.</param>
    /// <param name="statuses">Accepted status labels.</param>
    /// <returns>One when the status or risk level matches; otherwise zero.</returns>
    private static int IsStatus(BrowserScanResultRecord result, params string[] statuses) =>
        statuses.Any(status =>
            result.Status.Equals(status, StringComparison.OrdinalIgnoreCase) ||
            result.RiskLevel.Equals(status, StringComparison.OrdinalIgnoreCase))
            ? 1
            : 0;
}

/// <summary>
/// Development placeholder rate limiter that allows requests while preserving the production interface.
/// </summary>
/// <remarks>
/// Production should replace this with a Redis-backed fixed/sliding window limiter keyed by API key, user, device,
/// or privacy-safe client hash. This placeholder intentionally does not create a false sense of abuse protection.
/// </remarks>
public sealed class DevelopmentSubmissionRateLimiter : ISubmissionRateLimiter
{
    /// <inheritdoc />
    public Task<RateLimitDecision> CheckAsync(string sourceKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new RateLimitDecision(true, "Development placeholder allows submissions; production should use Redis-backed limits.", null));
    }
}

/// <summary>
/// Creates privacy-safe scalability keys from stored scan results and Site Safety provider evidence.
/// </summary>
public static class ScanScalabilityKeys
{
    /// <summary>
    /// Creates a signal hash from public-safe scan fields.
    /// </summary>
    /// <param name="request">Browser scan result request.</param>
    /// <returns>SHA-256 signal hash with a prefix for storage clarity.</returns>
    public static string CreateSignalHash(BrowserScanResultSaveRequest request)
    {
        var reasons = string.Join(",", (request.Reasons ?? Array.Empty<string>()).Select(reason => reason.Trim()).OrderBy(reason => reason, StringComparer.OrdinalIgnoreCase));
        var metadata = string.Join(",", (request.PrivacySafeMetadata ?? new Dictionary<string, string>())
            .Where(entry => !IsPrivateKey(entry.Key))
            .OrderBy(entry => entry.Key, StringComparer.OrdinalIgnoreCase)
            .Select(entry => $"{entry.Key.Trim()}={entry.Value.Trim()}"));
        var material = $"{request.Score}|{request.RiskLevel}|{request.Status}|{request.LinksScanned}|{request.RiskyLinksFound}|{request.SuspiciousLinksFound}|{request.DangerousLinksFound}|{request.RecommendedAction}|{reasons}|{metadata}";
        return $"sha256:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant()}";
    }

    /// <summary>
    /// Creates a dedupe key from normalized domain, URL hash, and signal hash.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="urlHash">SHA-256 URL hash.</param>
    /// <param name="signalHash">SHA-256 signal hash.</param>
    /// <returns>Dedupe key.</returns>
    public static ScanDedupeKey CreateDedupeKey(string domain, string urlHash, string signalHash) =>
        new(domain, urlHash, signalHash);

    /// <summary>
    /// Determines whether a metadata key is private and must not contribute to cache or dedupe material.
    /// </summary>
    /// <param name="key">Metadata key.</param>
    /// <returns>True when the key is unsafe.</returns>
    private static bool IsPrivateKey(string key) =>
        key.Contains("password", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("token", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("pageText", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("form", StringComparison.OrdinalIgnoreCase);
}
