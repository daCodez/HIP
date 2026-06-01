using HIP.Application.Browser;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed browser scan result repository using the generic HIP JSON record store.
/// </summary>
public sealed class EfBrowserScanResultRepository(HipRecordStore store) : IBrowserScanResultRepository
{
    private const string Partition = "browser-scan-result";

    /// <summary>
    /// Saves the latest privacy-safe scan result for a domain.
    /// </summary>
    /// <param name="result">Privacy-safe browser scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A task that completes when the record has been stored.</returns>
    public Task SaveAsync(BrowserScanResultRecord result, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, result.Domain, result, cancellationToken);

    /// <summary>
    /// Retrieves the latest browser plugin scan result for a normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored scan result, or null when none exists.</returns>
    public Task<BrowserScanResultRecord?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken) =>
        store.GetAsync<BrowserScanResultRecord>(Partition, domain, cancellationToken);
}
