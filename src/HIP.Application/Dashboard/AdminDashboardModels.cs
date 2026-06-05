using HIP.Domain.Risk;

namespace HIP.Application.Dashboard;

/// <summary>
/// Privacy-safe admin dashboard summary used by the Admin UI and API.
/// </summary>
/// <param name="Cards">Dashboard metric cards.</param>
/// <param name="RecentActivity">Existing cross-system activity summaries.</param>
/// <param name="ApiHealth">API health label.</param>
/// <param name="GeneratedAtUtc">UTC generation timestamp.</param>
/// <param name="DataSource">Primary real data source used for scan metrics.</param>
/// <param name="HasScanData">Whether stored browser scan data exists.</param>
/// <param name="TopRiskyDomains">Top risky domains from stored scan summaries.</param>
/// <param name="RecentScans">Recent privacy-safe browser scan summaries.</param>
/// <param name="RecentThreats">Recent privacy-safe threats filtered from real HIP evidence.</param>
public sealed record AdminDashboardSummary(
    IReadOnlyCollection<AdminDashboardCard> Cards,
    IReadOnlyCollection<AdminRecentActivityItem> RecentActivity,
    string ApiHealth,
    DateTimeOffset GeneratedAtUtc,
    string DataSource,
    bool HasScanData,
    IReadOnlyCollection<AdminRiskyDomainItem> TopRiskyDomains,
    IReadOnlyCollection<AdminRecentScanItem> RecentScans,
    IReadOnlyCollection<AdminRecentThreatItem> RecentThreats);

/// <summary>
/// Dashboard metric card.
/// </summary>
/// <param name="Key">Stable card key for clients/tests.</param>
/// <param name="Label">Display label.</param>
/// <param name="Value">Integer display value.</param>
/// <param name="Status">Short status label.</param>
/// <param name="IsPlaceholder">Whether the metric is placeholder/no-data.</param>
/// <param name="Description">Privacy-safe explanation.</param>
public sealed record AdminDashboardCard(
    string Key,
    string Label,
    int Value,
    string Status,
    bool IsPlaceholder,
    string Description);

/// <summary>
/// Privacy-safe recent activity summary.
/// </summary>
/// <param name="ActivityType">Activity category.</param>
/// <param name="TargetType">Target type label.</param>
/// <param name="TargetId">Public-safe target identifier.</param>
/// <param name="RiskLevel">Risk status when relevant.</param>
/// <param name="Summary">Privacy-safe summary.</param>
/// <param name="CreatedAtUtc">UTC activity timestamp.</param>
public sealed record AdminRecentActivityItem(
    string ActivityType,
    string TargetType,
    string TargetId,
    RiskStatus? RiskLevel,
    string Summary,
    DateTimeOffset CreatedAtUtc);

/// <summary>
/// Privacy-safe risky domain aggregate sourced from stored browser scans.
/// </summary>
/// <param name="Domain">Domain name.</param>
/// <param name="RiskyLinksFound">Total risky links found for the domain.</param>
/// <param name="DangerousLinksFound">Total dangerous links found for the domain.</param>
/// <param name="AverageHipScore">Average HIP score across stored scans.</param>
/// <param name="LatestScanUtc">Latest scan timestamp.</param>
/// <param name="ReasonSummary">Plain-English reason summary.</param>
public sealed record AdminRiskyDomainItem(
    string Domain,
    int RiskyLinksFound,
    int DangerousLinksFound,
    int AverageHipScore,
    DateTimeOffset LatestScanUtc,
    string ReasonSummary);

/// <summary>
/// Privacy-safe recent browser scan item for the dashboard.
/// </summary>
/// <param name="ScanResultId">Stable stored browser scan identifier used for admin detail navigation.</param>
/// <param name="Domain">Scanned domain.</param>
/// <param name="Score">HIP score.</param>
/// <param name="RiskLevel">Risk level label.</param>
/// <param name="LinksScanned">Number of links scanned.</param>
/// <param name="RiskyLinksFound">Number of risky links found.</param>
/// <param name="DangerousLinksFound">Number of dangerous links found.</param>
/// <param name="LastCheckedUtc">UTC scan timestamp.</param>
/// <param name="ReasonSummary">Plain-English reason summary.</param>
public sealed record AdminRecentScanItem(
    string ScanResultId,
    string Domain,
    int Score,
    string RiskLevel,
    int LinksScanned,
    int RiskyLinksFound,
    int DangerousLinksFound,
    DateTimeOffset LastCheckedUtc,
    string ReasonSummary);

/// <summary>
/// Privacy-safe recent threat row for the dashboard. It intentionally carries only domain-level
/// identifiers, URL hashes, summarized evidence, and related IDs so admins can triage without
/// exposing page text, form values, private messages, cookies, or raw browsing history.
/// </summary>
/// <param name="ThreatId">Stable dashboard threat identifier.</param>
/// <param name="Domain">Affected domain.</param>
/// <param name="UrlHash">Optional URL hash for page-level cases.</param>
/// <param name="TargetType">Target type such as Domain, Url, Feedback, ProviderEvidence, or Scan.</param>
/// <param name="Status">Workflow or scan status.</param>
/// <param name="SiteSafetyStatus">Site Safety status label.</param>
/// <param name="FinalHipScore">Final HIP score when available.</param>
/// <param name="Severity">Threat severity label.</param>
/// <param name="ConfidenceLevel">Confidence label for the evidence.</param>
/// <param name="ReasonSummary">Plain-English privacy-safe reason.</param>
/// <param name="WarningSummary">Optional warning summary.</param>
/// <param name="Source">Source evidence stream.</param>
/// <param name="RelatedScanId">Optional related browser scan or Site Safety scan ID.</param>
/// <param name="RelatedReviewId">Optional related review item ID.</param>
/// <param name="RelatedRuleId">Optional related rule ID.</param>
/// <param name="CreatedAtUtc">UTC creation or observation time.</param>
public sealed record AdminRecentThreatItem(
    string ThreatId,
    string Domain,
    string? UrlHash,
    string TargetType,
    string Status,
    string SiteSafetyStatus,
    int? FinalHipScore,
    string Severity,
    string ConfidenceLevel,
    string ReasonSummary,
    string? WarningSummary,
    string Source,
    string? RelatedScanId,
    string? RelatedReviewId,
    string? RelatedRuleId,
    DateTimeOffset CreatedAtUtc);
