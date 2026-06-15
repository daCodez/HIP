namespace HIP.Infrastructure.Persistence.Entities;

/// <summary>
/// Typed hot-path table row for privacy-safe browser scan results.
/// </summary>
/// <remarks>
/// This entity intentionally stores only public-safe scan summaries and URL hashes. It avoids the generic encrypted
/// JSON table for dashboard and lookup reads because those paths must not decrypt and filter every historical record.
/// </remarks>
public sealed class HipBrowserScanResultEntity
{
    /// <summary>
    /// Gets or sets the stable scan result identifier assigned by HIP.
    /// </summary>
    public string ScanResultId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the normalized scanned domain.
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the one-way hash of the scanned page URL.
    /// </summary>
    public string PageUrlHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets an optional raw URL slot reserved for explicit future opt-in policies.
    /// </summary>
    public string? StoredPageUrl { get; set; }

    /// <summary>
    /// Gets or sets the HIP client source that submitted the scan.
    /// </summary>
    public string ScanSource { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the final user-facing HIP score captured at scan time.
    /// </summary>
    public int Score { get; set; }

    /// <summary>
    /// Gets or sets the risk level captured at scan time.
    /// </summary>
    public string RiskLevel { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the status label captured at scan time.
    /// </summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets serialized public-safe plain-English reasons.
    /// </summary>
    public string ReasonsJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets the number of links scanned on the page.
    /// </summary>
    public int LinksScanned { get; set; }

    /// <summary>
    /// Gets or sets the number of links that required attention.
    /// </summary>
    public int RiskyLinksFound { get; set; }

    /// <summary>
    /// Gets or sets the number of suspicious or high-risk links found.
    /// </summary>
    public int SuspiciousLinksFound { get; set; }

    /// <summary>
    /// Gets or sets the number of dangerous or critical links found.
    /// </summary>
    public int DangerousLinksFound { get; set; }

    /// <summary>
    /// Gets or sets the UTC timestamp when the scan was performed.
    /// </summary>
    public DateTimeOffset LastCheckedUtc { get; set; }

    /// <summary>
    /// Gets or sets the recommended user action from HIP.
    /// </summary>
    public string RecommendedAction { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets serialized privacy-safe metadata such as plugin version and observed signal counts.
    /// </summary>
    public string PrivacySafeMetadataJson { get; set; } = "{}";

    /// <summary>
    /// Gets or sets the browser plugin version, copied out for quick dashboard filtering and debugging.
    /// </summary>
    public string? PluginVersion { get; set; }

    /// <summary>
    /// Gets or sets when HIP first persisted this typed scan row.
    /// </summary>
    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>
    /// Gets or sets when HIP last updated this typed scan row.
    /// </summary>
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
