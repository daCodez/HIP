namespace HIP.Application.Browser;

/// <summary>
/// Stores privacy-safe browser plugin scan results behind an abstraction so HIP can move from SQLite to production storage later.
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
}
