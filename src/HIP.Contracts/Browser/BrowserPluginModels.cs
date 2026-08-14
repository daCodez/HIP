namespace HIP.Application.Browser;

/// <summary>
/// Describes the page that the browser plugin wants HIP to score.
/// </summary>
/// <param name="Url">The current page URL observed by the plugin. Callers should avoid sending private page content with this request.</param>
/// <param name="Domain">The normalized domain for the current page, used for domain-level lookup and scoring.</param>
public sealed record BrowserScoreSiteRequest(
    string Url,
    string Domain);

/// <summary>
/// Returns the privacy-safe site score details shown in the browser plugin popup.
/// </summary>
/// <param name="Domain">The domain that was scored.</param>
/// <param name="Score">The legacy user-facing score kept for compatibility with older plugin code.</param>
/// <param name="FinalHipScore">The final HIP score after domain, page, and content signals are combined.</param>
/// <param name="DomainTrustScore">How trustworthy HIP currently considers the root domain.</param>
/// <param name="PageTrustScore">How trustworthy HIP currently considers this exact page or URL.</param>
/// <param name="ContentRiskScore">How risky the page content signals appear, such as forms, downloads, redirects, or suspicious links.</param>
/// <param name="FinalHipScoreExplanation">Plain-English explanation of the final score so users can understand the result.</param>
/// <param name="Status">The score label, such as Trusted, LimitedTrustData, Suspicious, or Dangerous.</param>
/// <param name="Reasons">Privacy-safe reasons that explain the score without exposing page text or form values.</param>
/// <param name="VerificationStatus">DNS or website verification status for the domain when known.</param>
/// <param name="SignedIdentityStatus">Signed identity status for the site when HIP identity data exists.</param>
/// <param name="LastCheckedUtc">When HIP last checked or calculated the score.</param>
/// <param name="PublicLookupUrl">The public lookup page for this domain.</param>
public sealed record BrowserScoreSiteResponse(
    string Domain,
    int Score,
    int FinalHipScore,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    string FinalHipScoreExplanation,
    string Status,
    IReadOnlyCollection<string> Reasons,
    string VerificationStatus,
    string SignedIdentityStatus,
    DateTimeOffset LastCheckedUtc,
    string PublicLookupUrl)
{
    /// <summary>Nullable score that the browser may display when authenticated evidence is sufficient.</summary>
    public int? DisplayScore { get; init; }

    /// <summary>Explicit score-presentation decision used to prevent misleading compatibility scores.</summary>
    public string ScorePresentation { get; init; } = HIP.Application.PublicLookup.PublicEvidencePresentation.ScoreWithheldInsufficientEvidence;

    /// <summary>Coverage of authenticated safety and trust evidence.</summary>
    public string EvidenceCoverage { get; init; } = HIP.Application.PublicLookup.PublicEvidencePresentation.CoverageInsufficient;

    /// <summary>Confidence in the authenticated evidence used for this response.</summary>
    public string EvidenceConfidence { get; init; } = HIP.Application.PublicLookup.PublicEvidencePresentation.ConfidenceNone;

    /// <summary>Normalized identity state: Unverified, Pending, or Verified.</summary>
    public string IdentityStatus { get; init; } = "Unverified";

    /// <summary>Public-safe certificate application decision state.</summary>
    public string CertificateApplicationStatus { get; init; } = "NotStarted";

    /// <summary>Plain-English current certificate lifecycle stage.</summary>
    public string CertificateProgressStatus { get; init; } = "No certificate application";

    /// <summary>Public-safe continuous monitoring lifecycle state.</summary>
    public string MonitoringStatus { get; init; } = "Not enabled";

    /// <summary>Public-safe source of the authoritative assessment.</summary>
    public string DataSource { get; init; } = "NoStoredData";
}

/// <summary>
/// Describes links observed on a page so HIP can classify only the URLs, not the page body.
/// </summary>
/// <param name="PageUrl">The page that contained the links. The backend must handle this according to the privacy storage policy.</param>
/// <param name="Links">The discovered link URLs to classify.</param>
public sealed record BrowserScanLinksRequest(
    string PageUrl,
    IReadOnlyCollection<string> Links);

/// <summary>
/// Returns the risk decision for one link observed by the browser plugin.
/// </summary>
/// <param name="Url">The link URL that was classified.</param>
/// <param name="Domain">The link domain used for lookup and risk decisions.</param>
/// <param name="RiskLevel">The link risk level, such as Safe, Unknown, Suspicious, Dangerous, or Critical.</param>
/// <param name="Score">The current HIP score for the link target.</param>
/// <param name="Reasons">Privacy-safe reasons for the link decision.</param>
/// <param name="RecommendedAction">The action the plugin should take, such as Allow, ShowLabel, RouteToSafetyPage, or Block.</param>
/// <param name="RequiresIcon">Whether the plugin should display a visible marker beside this link.</param>
/// <param name="Label">Optional short label to show beside risky links.</param>
/// <param name="PublicLookupUrl">The public lookup URL for the link target.</param>
/// <param name="SafetyPageUrl">Optional safety page URL when the link should be routed through a warning flow.</param>
public sealed record BrowserLinkRiskResult(
    string Url,
    string Domain,
    string RiskLevel,
    int Score,
    IReadOnlyCollection<string> Reasons,
    string RecommendedAction,
    bool RequiresIcon,
    string? Label,
    string PublicLookupUrl,
    string? SafetyPageUrl);

/// <summary>
/// Returns all link risk results for a browser-observed page scan.
/// </summary>
/// <param name="PageUrl">The scanned page URL from the request.</param>
/// <param name="Results">Risk results for each submitted link.</param>
public sealed record BrowserScanLinksResponse(
    string PageUrl,
    IReadOnlyCollection<BrowserLinkRiskResult> Results);
