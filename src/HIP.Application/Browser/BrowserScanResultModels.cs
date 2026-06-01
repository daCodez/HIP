namespace HIP.Application.Browser;

/// <summary>
/// Represents a privacy-safe browser plugin scan result stored by HIP for later scoring, lookup, and dashboard use.
/// </summary>
/// <param name="ScanResultId">Stable scan result identifier assigned by HIP.</param>
/// <param name="Domain">Normalized domain scanned by the browser plugin.</param>
/// <param name="PageUrlHash">One-way hash of the scanned page URL; HIP stores this instead of the full URL by default.</param>
/// <param name="StoredPageUrl">Optional full URL storage slot reserved for future explicit opt-in policies.</param>
/// <param name="ScanSource">Source client name, expected to be BrowserPlugin for this MVP path.</param>
/// <param name="Score">HIP score at scan time.</param>
/// <param name="RiskLevel">Risk level reported by the plugin/API.</param>
/// <param name="Status">Status label reported by the plugin/API.</param>
/// <param name="Reasons">Plain-English scoring reasons safe for public or admin display.</param>
/// <param name="LinksScanned">Number of links scanned on the current page.</param>
/// <param name="RiskyLinksFound">Number of links requiring attention.</param>
/// <param name="SuspiciousLinksFound">Number of suspicious or high-risk links.</param>
/// <param name="DangerousLinksFound">Number of dangerous or critical links.</param>
/// <param name="LastCheckedUtc">UTC timestamp when the browser plugin produced the scan result.</param>
/// <param name="RecommendedAction">Recommended HIP action such as Allow or RouteToSafetyPage.</param>
/// <param name="PrivacySafeMetadata">Small metadata dictionary that must not contain page text, form values, or private content.</param>
public sealed record BrowserScanResultRecord(
    string ScanResultId,
    string Domain,
    string PageUrlHash,
    string? StoredPageUrl,
    string ScanSource,
    int Score,
    string RiskLevel,
    string Status,
    IReadOnlyCollection<string> Reasons,
    int LinksScanned,
    int RiskyLinksFound,
    int SuspiciousLinksFound,
    int DangerousLinksFound,
    DateTimeOffset LastCheckedUtc,
    string RecommendedAction,
    IReadOnlyDictionary<string, string> PrivacySafeMetadata);

/// <summary>
/// API request from the browser plugin for saving a privacy-safe scan summary.
/// </summary>
/// <param name="Domain">Domain scanned by the plugin.</param>
/// <param name="PageUrl">Current page URL; HIP hashes this by default and does not store page text.</param>
/// <param name="Score">HIP score from 0 through 100.</param>
/// <param name="RiskLevel">Risk level associated with the scan.</param>
/// <param name="Status">Status label associated with the scan.</param>
/// <param name="Reasons">Plain-English reasons shown to the user.</param>
/// <param name="LinksScanned">Number of page links scanned.</param>
/// <param name="RiskyLinksFound">Number of risky links found.</param>
/// <param name="SuspiciousLinksFound">Number of suspicious/high-risk links found.</param>
/// <param name="DangerousLinksFound">Number of dangerous/critical links found.</param>
/// <param name="RecommendedAction">Recommended action for the scanned site.</param>
/// <param name="PrivacySafeMetadata">Optional privacy-safe counts and context; private content is rejected by validation.</param>
public sealed record BrowserScanResultSaveRequest(
    string Domain,
    string PageUrl,
    int Score,
    string RiskLevel,
    string Status,
    IReadOnlyCollection<string>? Reasons,
    int LinksScanned,
    int RiskyLinksFound,
    int SuspiciousLinksFound,
    int DangerousLinksFound,
    string RecommendedAction,
    IReadOnlyDictionary<string, string>? PrivacySafeMetadata);

/// <summary>
/// API response returned after HIP stores a browser scan result.
/// </summary>
/// <param name="Saved">Whether the result was saved.</param>
/// <param name="Domain">Normalized domain saved.</param>
/// <param name="LastCheckedUtc">UTC timestamp assigned to the stored scan result.</param>
public sealed record BrowserScanResultSaveResponse(
    bool Saved,
    string Domain,
    DateTimeOffset LastCheckedUtc);

/// <summary>
/// API response for the latest privacy-safe browser scan result for a domain.
/// </summary>
/// <param name="Domain">Normalized domain.</param>
/// <param name="Score">HIP score at scan time.</param>
/// <param name="RiskLevel">Risk level at scan time.</param>
/// <param name="Status">Status label at scan time.</param>
/// <param name="Reasons">Plain-English reasons safe to display.</param>
/// <param name="LinksScanned">Number of page links scanned.</param>
/// <param name="RiskyLinksFound">Number of risky links found.</param>
/// <param name="SuspiciousLinksFound">Number of suspicious/high-risk links found.</param>
/// <param name="DangerousLinksFound">Number of dangerous/critical links found.</param>
/// <param name="LastCheckedUtc">UTC timestamp assigned to the stored scan result.</param>
/// <param name="RecommendedAction">Recommended HIP action.</param>
/// <param name="PrivacySafeMetadata">Privacy-safe metadata retained with the scan.</param>
public sealed record BrowserScanResultResponse(
    string Domain,
    int Score,
    string RiskLevel,
    string Status,
    IReadOnlyCollection<string> Reasons,
    int LinksScanned,
    int RiskyLinksFound,
    int SuspiciousLinksFound,
    int DangerousLinksFound,
    DateTimeOffset LastCheckedUtc,
    string RecommendedAction,
    IReadOnlyDictionary<string, string> PrivacySafeMetadata)
{
    /// <summary>
    /// Creates an API response from the stored record while intentionally omitting URL hashes and any sensitive storage fields.
    /// </summary>
    /// <param name="record">Stored browser scan result.</param>
    /// <returns>Privacy-safe API response.</returns>
    public static BrowserScanResultResponse From(BrowserScanResultRecord record) =>
        new(
            record.Domain,
            record.Score,
            record.RiskLevel,
            record.Status,
            record.Reasons,
            record.LinksScanned,
            record.RiskyLinksFound,
            record.SuspiciousLinksFound,
            record.DangerousLinksFound,
            record.LastCheckedUtc,
            record.RecommendedAction,
            record.PrivacySafeMetadata);
}

/// <summary>
/// Error shape used when a browser scan result fails validation.
/// </summary>
/// <param name="Error">Plain-English validation error.</param>
public sealed record BrowserScanResultErrorResponse(string Error);
