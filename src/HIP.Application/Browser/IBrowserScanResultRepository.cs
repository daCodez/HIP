namespace HIP.Application.Browser;

/// <summary>
/// Stores privacy-safe browser plugin scan results behind an abstraction so HIP can use durable production storage.
/// </summary>
public interface IBrowserScanResultRepository
{
    /// <summary>
    /// Saves the latest scan result for a normalized domain.
    /// </summary>
    /// <param name="result">Privacy-safe browser scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes when the result has been saved.</returns>
    Task SaveAsync(BrowserScanResultRecord result, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the latest saved browser scan result for a normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The latest result for the domain, or null when HIP has not seen it yet.</returns>
    Task<BrowserScanResultRecord?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken);

    /// <summary>
    /// Lists stored browser scan results for privacy-safe aggregation in admin dashboards.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Stored scan results sorted by repository implementation preference.</returns>
    Task<IReadOnlyCollection<BrowserScanResultRecord>> ListAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Lists a bounded number of recent browser scan results for dashboard tables without forcing full history reads.
    /// </summary>
    /// <param name="maxCount">Maximum number of recent scan records to return.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Recent scan results, newest first.</returns>
    Task<IReadOnlyCollection<BrowserScanResultRecord>> ListRecentAsync(int maxCount, CancellationToken cancellationToken);

    /// <summary>
    /// Counts distinct normalized domains across all stored browser scan results.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The number of distinct stored scan domains.</returns>
    Task<int> CountDistinctDomainsAsync(CancellationToken cancellationToken);
}
