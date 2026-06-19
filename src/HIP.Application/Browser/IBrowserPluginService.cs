namespace HIP.Application.Browser;

/// <summary>
/// Provides browser-plugin-facing scoring and link classification operations.
/// </summary>
public interface IBrowserPluginService
{
    /// <summary>
    /// Scores the current website for the browser plugin popup using privacy-safe site signals.
    /// </summary>
    /// <param name="request">The current page and domain observed by the plugin.</param>
    /// <param name="cancellationToken">Token used to cancel the score lookup.</param>
    /// <returns>The current site score, status, reasons, and public lookup link.</returns>
    Task<BrowserScoreSiteResponse> ScoreSiteAsync(BrowserScoreSiteRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Classifies links found on a page without requiring the plugin to send page text or form values.
    /// </summary>
    /// <param name="request">The page URL and discovered links to classify.</param>
    /// <param name="cancellationToken">Token used to cancel link classification.</param>
    /// <returns>Per-link risk decisions that tell the plugin which links need labels or safety routing.</returns>
    Task<BrowserScanLinksResponse> ScanLinksAsync(BrowserScanLinksRequest request, CancellationToken cancellationToken);
}
