using System.Collections.Concurrent;

namespace HIP.Application.Browser;

/// <summary>
/// In-memory browser scan result repository used by tests and development hosts without configured persistence.
/// </summary>
public sealed class InMemoryBrowserScanResultRepository : IBrowserScanResultRepository
{
    private readonly ConcurrentDictionary<string, BrowserScanResultRecord> resultsById = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Saves or replaces the latest scan result for the result domain.
    /// </summary>
    /// <param name="result">Privacy-safe browser scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A completed task once the in-memory store has been updated.</returns>
    public Task SaveAsync(BrowserScanResultRecord result, CancellationToken cancellationToken)
    {
        resultsById[result.ScanResultId] = result;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves the latest scan result stored for a normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The latest result, or null when none is stored.</returns>
    public Task<BrowserScanResultRecord?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var result = resultsById.Values
            .Where(item => item.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.LastCheckedUtc)
            .FirstOrDefault();

        return Task.FromResult(result);
    }

    /// <summary>
    /// Lists all stored scan results for aggregation tests and development dashboards.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>All stored scan results, newest first.</returns>
    public Task<IReadOnlyCollection<BrowserScanResultRecord>> ListAsync(CancellationToken cancellationToken)
    {
        var results = resultsById.Values
            .OrderByDescending(item => item.LastCheckedUtc)
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<BrowserScanResultRecord>>(results);
    }

    /// <summary>
    /// Lists the most recent in-memory scan results for dashboard tables without exposing private page content.
    /// </summary>
    /// <param name="maxCount">Maximum number of scan results to return.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Recent scan results, newest first.</returns>
    public Task<IReadOnlyCollection<BrowserScanResultRecord>> ListRecentAsync(int maxCount, CancellationToken cancellationToken)
    {
        var boundedMax = Math.Max(0, maxCount);
        var results = resultsById.Values
            .OrderByDescending(item => item.LastCheckedUtc)
            .Take(boundedMax)
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<BrowserScanResultRecord>>(results);
    }
}
