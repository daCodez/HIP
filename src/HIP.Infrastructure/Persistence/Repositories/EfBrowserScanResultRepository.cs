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
        store.SaveAsync(Partition, result.ScanResultId, result, cancellationToken);

    /// <summary>
    /// Retrieves the latest browser plugin scan result for a normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>The stored scan result, or null when none exists.</returns>
    public async Task<BrowserScanResultRecord?> GetLatestByDomainAsync(string domain, CancellationToken cancellationToken)
    {
        var results = await ListAsync(cancellationToken);
        return results
            .Where(result => result.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(result => result.LastCheckedUtc)
            .FirstOrDefault();
    }

    /// <summary>
    /// Lists stored browser plugin scan results for privacy-safe dashboard aggregation.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Stored scan results, newest first.</returns>
    public async Task<IReadOnlyCollection<BrowserScanResultRecord>> ListAsync(CancellationToken cancellationToken)
    {
        var results = await store.ListAsync<BrowserScanResultRecord>(Partition, cancellationToken);
        return results
            .OrderByDescending(result => result.LastCheckedUtc)
            .ToArray();
    }
}
