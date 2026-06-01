namespace HIP.Application.SiteSafety;

/// <summary>
/// Scans a website URL and privacy-safe client observations for page-level safety risks.
/// </summary>
public interface ISiteSafetyScanner
{
    /// <summary>
    /// Runs a Site Safety Scan without executing remote scripts, downloading files, or submitting forms.
    /// </summary>
    /// <param name="request">The URL and optional privacy-safe observations to scan.</param>
    /// <param name="cancellationToken">Token used to cancel scan work.</param>
    /// <returns>A page-level safety scan result with score impact details.</returns>
    Task<SiteSafetyScanResult> ScanAsync(SiteSafetyScanRequest request, CancellationToken cancellationToken);
}
