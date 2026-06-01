using System.Collections.Concurrent;

namespace HIP.Application.Browser;

/// <summary>
/// In-memory browser scan result repository used by tests and development hosts without configured persistence.
/// </summary>
public sealed class InMemoryBrowserScanResultRepository : IBrowserScanResultRepository
{
    private readonly ConcurrentDictionary<string, BrowserScanResultRecord> resultsByDomain = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Saves or replaces the latest scan result for the result domain.
    /// </summary>
    /// <param name="result">Privacy-safe browser scan result.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>A completed task once the in-memory store has been updated.</returns>
    public Task SaveAsync(BrowserScanResultRecord result, CancellationToken cancellationToken)
    {
        resultsByDomain[result.Domain] = result;
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
        resultsByDomain.TryGetValue(domain, out var result);
        return Task.FromResult(result);
    }
}
