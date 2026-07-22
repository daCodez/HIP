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

/// <summary>
/// Accepts unattested browser scan summaries without allowing callers to grant their evidence authoritative trust.
/// </summary>
public interface IUntrustedBrowserScanResultSubmissionService
{
    /// <summary>
    /// Saves an anonymous client submission with server-owned untrusted provenance and receipt time.
    /// </summary>
    /// <param name="request">Untrusted browser scan result request.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>Save confirmation with the normalized domain and server receipt timestamp.</returns>
    Task<BrowserScanResultSaveResponse> SaveUntrustedAsync(
        BrowserScanResultSaveRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Accepts a privacy-safe submission whose active registered device proved possession.</summary>
public interface IRegisteredDeviceBrowserScanResultSubmissionService
{
    Task<BrowserScanResultSaveResponse> SaveRegisteredDeviceAsync(
        BrowserScanResultSaveRequest request,
        CancellationToken cancellationToken);
}
