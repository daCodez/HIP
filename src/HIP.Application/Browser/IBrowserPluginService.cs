namespace HIP.Application.Browser;

public interface IBrowserPluginService
{
    Task<BrowserScoreSiteResponse> ScoreSiteAsync(BrowserScoreSiteRequest request, CancellationToken cancellationToken);

    Task<BrowserScanLinksResponse> ScanLinksAsync(BrowserScanLinksRequest request, CancellationToken cancellationToken);
}
