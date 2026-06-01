using HIP.Domain.Risk;

namespace HIP.Application.PublicLookup;

/// <summary>
/// Public-safe HIP lookup response for a domain.
/// </summary>
/// <param name="Domain">Normalized domain.</param>
/// <param name="Score">Compatibility score value; no-data results use 0 with Unknown status until nullable clients are adopted.</param>
/// <param name="FinalHipScore">Final HIP score value; no-data results use 0 with Unknown status until nullable clients are adopted.</param>
/// <param name="Status">Current public risk status.</param>
/// <param name="RiskLevel">Risk level text shown by clients.</param>
/// <param name="VerificationStatus">Domain verification status.</param>
/// <param name="KnownRisks">Known public risk summaries.</param>
/// <param name="Reasons">Plain-English reasons safe for public display.</param>
/// <param name="Explanations">Detailed public-safe explanations.</param>
/// <param name="RecommendedAction">Recommended user action.</param>
/// <param name="LastCheckedUtc">Last scan or lookup timestamp.</param>
/// <param name="SignedIdentityStatus">Signed identity status.</param>
/// <param name="VerificationMethod">Domain verification method.</param>
/// <param name="VerifiedOrganization">Verified organization, when configured.</param>
/// <param name="SignatureStatus">Signature status when available.</param>
/// <param name="IdentityVerificationStatus">Identity verification status.</param>
/// <param name="SignatureValid">Whether a signature was valid, unknown, or not configured.</param>
/// <param name="PublicBadgeEligible">Whether a live public badge can be shown.</param>
/// <param name="PublicLookupUrl">Shareable public lookup URL.</param>
/// <param name="ScoreBreakdown">Public-safe score component breakdown.</param>
/// <param name="LinksScanned">Number of links scanned in the latest browser plugin scan.</param>
/// <param name="RiskyLinksFound">Number of risky links found in the latest browser plugin scan.</param>
/// <param name="SuspiciousLinksFound">Number of suspicious links found in the latest browser plugin scan.</param>
/// <param name="DangerousLinksFound">Number of dangerous links found in the latest browser plugin scan.</param>
/// <param name="DataSource">Where public lookup data came from.</param>
/// <param name="Message">Plain-English state message such as no stored scan data.</param>
public sealed record PublicDomainLookupResponse(
    string Domain,
    int Score,
    int FinalHipScore,
    RiskStatus Status,
    string RiskLevel,
    string VerificationStatus,
    IReadOnlyCollection<string> KnownRisks,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Explanations,
    string RecommendedAction,
    DateTimeOffset LastCheckedUtc,
    string SignedIdentityStatus,
    string VerificationMethod,
    string? VerifiedOrganization,
    string SignatureStatus,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    bool PublicBadgeEligible,
    string PublicLookupUrl,
    IReadOnlyCollection<ScoreBreakdownItem> ScoreBreakdown,
    int? LinksScanned,
    int? RiskyLinksFound,
    int? SuspiciousLinksFound,
    int? DangerousLinksFound,
    string DataSource,
    string Message);

/// <summary>
/// Public-safe score component used by lookup pages and API clients.
/// </summary>
/// <param name="Category">Score category name.</param>
/// <param name="Score">Score value.</param>
/// <param name="Status">Risk status mapped from the score.</param>
/// <param name="Explanation">Plain-English explanation.</param>
/// <param name="Reasons">Supporting reasons.</param>
public sealed record ScoreBreakdownItem(
    string Category,
    int Score,
    RiskStatus Status,
    string Explanation,
    IReadOnlyCollection<string> Reasons);
