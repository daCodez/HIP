namespace HIP.Application.Browser;

/// <summary>
/// Write boundary for browser scan results.
/// </summary>
/// <remarks>
/// This interface separates scan ingestion from dashboard and public lookup reads so high-scale deployments can use
/// command handlers, queues, and write-optimized storage without coupling them to read projections.
/// </remarks>
public interface IBrowserScanResultWriteService
{
    /// <summary>
    /// Saves a privacy-safe browser scan result after validation and hashing.
    /// </summary>
    /// <param name="request">Browser plugin scan result request.</param>
    /// <param name="cancellationToken">Token used to cancel the write.</param>
    /// <returns>Save confirmation.</returns>
    Task<BrowserScanResultSaveResponse> SaveAsync(BrowserScanResultSaveRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Read boundary for browser scan result projections.
/// </summary>
/// <remarks>
/// Public lookup and dashboard features should depend on this query boundary instead of write repositories. A future
/// implementation can read from Redis, PostgreSQL projections, or materialized dashboard views.
/// </remarks>
public interface IBrowserScanResultQueryService
{
    /// <summary>
    /// Gets the latest privacy-safe browser scan projection for a domain.
    /// </summary>
    /// <param name="domain">Domain requested by a client.</param>
    /// <param name="cancellationToken">Token used to cancel the read.</param>
    /// <returns>Latest scan response, or null when no scan exists.</returns>
    Task<BrowserScanResultResponse?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent privacy-safe scan projections for dashboard reads.
    /// </summary>
    /// <param name="maxCount">Maximum number of recent scans to return.</param>
    /// <param name="cancellationToken">Token used to cancel the read.</param>
    /// <returns>Recent scan responses, newest first.</returns>
    Task<IReadOnlyCollection<BrowserScanResultResponse>> ListRecentAsync(int maxCount, CancellationToken cancellationToken);
}
