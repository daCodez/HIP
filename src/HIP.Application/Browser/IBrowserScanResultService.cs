namespace HIP.Application.Browser;

/// <summary>
/// Coordinates validation, hashing, and persistence for browser plugin scan summaries.
/// </summary>
public interface IBrowserScanResultService
{
    /// <summary>
    /// Saves a privacy-safe browser scan result after validating that no private page content is included.
    /// </summary>
    /// <param name="request">Browser plugin scan result request.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>Save confirmation with normalized domain and timestamp.</returns>
    Task<BrowserScanResultSaveResponse> SaveAsync(BrowserScanResultSaveRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the latest privacy-safe browser scan result for a domain.
    /// </summary>
    /// <param name="domain">Domain requested by a client.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The latest scan result, or null when HIP has no browser scan data for the domain.</returns>
    Task<BrowserScanResultResponse?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken);
}
