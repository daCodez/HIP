using System.Security.Cryptography;
using System.Text;
using HIP.Application.Browser;
using HIP.Application.Scalability;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfScanResultCache(HipRecordStore store) : IScanResultCache
{
    private const string Partition = "scan-result-cache";

    public async Task<ScanResultCacheEntry?> GetFreshAsync(string domain, CancellationToken cancellationToken)
    {
        var normalizedDomain = NormalizeDomain(domain);
        var entry = await store.GetAsync<ScanResultCacheEntry>(Partition, normalizedDomain, cancellationToken);
        if (entry is null)
        {
            return null;
        }

        if (entry.ExpiresAtUtc > DateTimeOffset.UtcNow)
        {
            return entry;
        }

        await store.RemoveAsync(Partition, normalizedDomain, cancellationToken);
        return null;
    }

    public Task StoreAsync(BrowserScanResultRecord result, TimeSpan ttl, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = new ScanResultCacheEntry(
            NormalizeDomain(result.Domain),
            result,
            now,
            now.Add(ttl));

        return store.SaveAsync(Partition, entry.Domain, entry, cancellationToken);
    }

    private static string NormalizeDomain(string domain) =>
        domain.Trim().ToLowerInvariant();
}

public sealed class EfScanIngestionQueue(HipRecordStore store) : IScanIngestionQueue
{
    private const string Partition = "scan-ingestion-queue";

    public Task EnqueueAsync(ScanIngestionRequest request, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, request.RequestId, request, cancellationToken);

    public async Task<IReadOnlyCollection<ScanIngestionRequest>> DequeueBatchAsync(int maxCount, CancellationToken cancellationToken)
    {
        var boundedMax = Math.Max(0, maxCount);
        if (boundedMax == 0)
        {
            return Array.Empty<ScanIngestionRequest>();
        }

        var queued = await store.ListAsync<ScanIngestionRequest>(Partition, cancellationToken);
        var batch = queued
            .OrderBy(request => request.RequestedAtUtc)
            .ThenBy(request => request.RequestId, StringComparer.Ordinal)
            .Take(boundedMax)
            .ToArray();

        foreach (var request in batch)
        {
            await store.RemoveAsync(Partition, request.RequestId, cancellationToken);
        }

        return batch;
    }
}

public sealed class EfScanResultDedupeService(HipRecordStore store) : IScanResultDedupeService
{
    private const string Partition = "scan-result-dedupe";

    public async Task<bool> TryAcceptAsync(ScanDedupeKey key, TimeSpan window, CancellationToken cancellationToken)
    {
        var id = Fingerprint(key);
        var marker = await store.GetAsync<ScanDedupeMarker>(Partition, id, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        if (marker is not null && marker.ExpiresAtUtc > now)
        {
            return false;
        }

        await store.SaveAsync(Partition, id, new ScanDedupeMarker(id, now.Add(window)), cancellationToken);
        return true;
    }

    private static string Fingerprint(ScanDedupeKey key)
    {
        var normalized = $"{key.Domain.Trim().ToLowerInvariant()}|{key.UrlHash.Trim().ToLowerInvariant()}|{key.SignalHash.Trim().ToLowerInvariant()}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
    }

    private sealed record ScanDedupeMarker(string Fingerprint, DateTimeOffset ExpiresAtUtc);
}

/// <summary>
/// Persists the current dashboard scan aggregate so the admin dashboard can read live scan counters.
/// </summary>
/// <param name="store">Encrypted generic record store used for the MVP aggregate projection.</param>
public sealed class EfDashboardScanAggregateStore(HipRecordStore store) : IDashboardScanAggregateStore
{
    private const string Partition = "dashboard-scan-aggregate";
    private const string CurrentId = "current";
    private static readonly SemaphoreSlim AggregateUpdateLock = new(1, 1);

    /// <summary>
    /// Updates the single current aggregate with one new scan result.
    /// The lock protects the read-modify-write counter projection inside one HIP process; future typed tables should use
    /// database-side atomic increments for multi-instance scale.
    /// </summary>
    /// <param name="result">Privacy-safe scan result to project into dashboard counters.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    public async Task UpdateAsync(BrowserScanResultRecord result, CancellationToken cancellationToken)
    {
        await AggregateUpdateLock.WaitAsync(cancellationToken);
        try
        {
            var aggregate = await GetAsync(cancellationToken);
            var today = result.LastCheckedUtc.UtcDateTime.Date == DateTimeOffset.UtcNow.UtcDateTime.Date ? 1 : 0;
            var updated = aggregate with
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

            await store.SaveAsync(Partition, CurrentId, updated, cancellationToken);
        }
        finally
        {
            AggregateUpdateLock.Release();
        }
    }

    /// <summary>
    /// Reads the current dashboard scan aggregate or an explicit empty aggregate when no scans have been stored yet.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Current aggregate counters for admin dashboard live data.</returns>
    public async Task<DashboardScanAggregate> GetAsync(CancellationToken cancellationToken) =>
        await store.GetAsync<DashboardScanAggregate>(Partition, CurrentId, cancellationToken)
        ?? Empty();

    /// <summary>
    /// Creates an explicit no-data aggregate for fresh development databases.
    /// </summary>
    /// <returns>Empty dashboard aggregate.</returns>
    private static DashboardScanAggregate Empty() =>
        new(0, 0, 0, 0, 0, 0, 0, 0, 0, DateTimeOffset.MinValue);

    /// <summary>
    /// Maps legacy and current status labels into the dashboard counter buckets.
    /// </summary>
    /// <param name="result">Stored browser scan result.</param>
    /// <param name="statuses">Accepted labels for this counter.</param>
    /// <returns>One when the scan matches a requested status, otherwise zero.</returns>
    private static int IsStatus(BrowserScanResultRecord result, params string[] statuses) =>
        statuses.Any(status =>
            result.Status.Equals(status, StringComparison.OrdinalIgnoreCase) ||
            result.RiskLevel.Equals(status, StringComparison.OrdinalIgnoreCase))
            ? 1
            : 0;
}
