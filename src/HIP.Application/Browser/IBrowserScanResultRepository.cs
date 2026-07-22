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
    /// Retrieves the latest scan that HIP explicitly marked as server-authoritative for public scoring.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The latest authoritative result, or null when HIP has no authoritative evidence for the domain.</returns>
    async Task<BrowserScanResultRecord?> GetLatestAuthoritativeByDomainAsync(
        string domain,
        CancellationToken cancellationToken)
    {
        var latest = await GetLatestByDomainAsync(domain, cancellationToken);
        if (latest is null || BrowserScanResultProvenance.IsServerAuthoritative(latest))
        {
            return latest;
        }

        return (await ListAsync(cancellationToken))
            .Where(result => result.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
            .Where(BrowserScanResultProvenance.IsServerAuthoritative)
            .OrderByDescending(result => result.LastCheckedUtc)
            .FirstOrDefault();
    }

    /// <summary>
    /// Lists stored browser scan results for privacy-safe aggregation in admin dashboards.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Stored scan results sorted by repository implementation preference.</returns>
    Task<IReadOnlyCollection<BrowserScanResultRecord>> ListAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Lists a bounded number of recent server-authoritative scan results for dashboard tables.
    /// </summary>
    /// <param name="maxCount">Maximum number of recent scan records to return.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Recent authoritative scan results, newest first.</returns>
    Task<IReadOnlyCollection<BrowserScanResultRecord>> ListRecentAsync(int maxCount, CancellationToken cancellationToken);

    /// <summary>
    /// Counts distinct normalized domains across server-authoritative browser scan results.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The number of distinct authoritative scan domains.</returns>
    Task<int> CountDistinctDomainsAsync(CancellationToken cancellationToken);
}
