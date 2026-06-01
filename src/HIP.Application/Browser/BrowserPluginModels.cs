namespace HIP.Application.Browser;

public sealed record BrowserScoreSiteRequest(
    string Url,
    string Domain);

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
    string PublicLookupUrl);

public sealed record BrowserScanLinksRequest(
    string PageUrl,
    IReadOnlyCollection<string> Links);

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

public sealed record BrowserScanLinksResponse(
    string PageUrl,
    IReadOnlyCollection<BrowserLinkRiskResult> Results);
