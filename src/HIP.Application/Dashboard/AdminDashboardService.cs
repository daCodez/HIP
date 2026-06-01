using HIP.Application.Browser;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Dashboard;

/// <summary>
/// Aggregates privacy-safe HIP dashboard metrics from stored browser scans and administrative workflow services.
/// </summary>
/// <param name="browserScanResultRepository">Repository containing stored browser plugin scan summaries.</param>
/// <param name="riskFindingRepository">Repository containing privacy-safe risk finding reports.</param>
/// <param name="reviewQueueService">Review queue service.</param>
/// <param name="appealService">Appeal service.</param>
/// <param name="reputationOverrideService">Reputation override service.</param>
/// <param name="auditLogService">Audit log service.</param>
/// <param name="ruleRepository">Rule repository.</param>
/// <param name="generatedRuleCandidateRepository">Generated rule candidate repository.</param>
public sealed class AdminDashboardService(
    IBrowserScanResultRepository browserScanResultRepository,
    IRiskFindingReportRepository riskFindingRepository,
    IReviewQueueService reviewQueueService,
    IAppealService appealService,
    IReputationOverrideService reputationOverrideService,
    IAuditLogService auditLogService,
    IRuleRepository ruleRepository,
    IGeneratedRuleCandidateRepository generatedRuleCandidateRepository) : IAdminDashboardService
{
    /// <summary>
    /// Builds a privacy-safe dashboard summary using stored browser scan results as the primary real scan source.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel repository reads.</param>
    /// <returns>Admin dashboard summary.</returns>
    public async Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken)
    {
        var browserScans = await browserScanResultRepository.ListAsync(cancellationToken);
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        var reviews = reviewQueueService.List();
        var appeals = appealService.List();
        var overrides = reputationOverrideService.List();
        var auditLogs = auditLogService.List();
        var rules = await ruleRepository.ListAsync(cancellationToken);
        var candidates = await generatedRuleCandidateRepository.ListAsync(cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var hasScanData = browserScans.Count > 0;
        var totalScans = browserScans.Count;
        var domainsScanned = browserScans.Select(scan => scan.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var linksScanned = browserScans.Sum(scan => scan.LinksScanned);
        var riskyLinksFound = browserScans.Sum(scan => scan.RiskyLinksFound);
        var suspiciousLinksFound = browserScans.Sum(scan => scan.SuspiciousLinksFound);
        var dangerousLinksFound = browserScans.Sum(scan => scan.DangerousLinksFound);
        var scansLast24Hours = browserScans.Count(scan => scan.LastCheckedUtc >= now.AddHours(-24));
        var scansLast7Days = browserScans.Count(scan => scan.LastCheckedUtc >= now.AddDays(-7));
        var averageHipScore = hasScanData ? (int)Math.Round(browserScans.Average(scan => scan.Score)) : 0;
        var latestScanUtc = browserScans.OrderByDescending(scan => scan.LastCheckedUtc).FirstOrDefault()?.LastCheckedUtc;

        var riskyFindings = findings.Count(finding => IsRisky(finding.RiskLevel));
        var dangerousDomains = findings
            .Where(finding => finding.RiskLevel is RiskStatus.Dangerous or RiskStatus.Critical)
            .Select(finding => finding.Domain)
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var cards = new[]
        {
            Card("totalScans", "Total Scans", totalScans, hasScanData ? "BrowserPluginScanResults" : "No Data", !hasScanData, "Stored privacy-safe browser plugin scans."),
            Card("domainsScanned", "Domains Scanned", domainsScanned, hasScanData ? "Distinct" : "No Data", !hasScanData, "Distinct domains with stored browser scan results."),
            Card("linksScanned", "Links Scanned", linksScanned, hasScanData ? "Total" : "No Data", !hasScanData, "Total anchor href values scanned by browser clients."),
            Card("riskyLinksFound", "Risky Links", riskyLinksFound, riskyLinksFound > 0 ? "Needs Review" : "Clear", !hasScanData, "Total risky links found in stored browser scans."),
            Card("suspiciousLinksFound", "Suspicious Links", suspiciousLinksFound, suspiciousLinksFound > 0 ? "Watch" : "Clear", !hasScanData, "Total suspicious/high-risk links found in stored browser scans."),
            Card("dangerousLinksFound", "Dangerous Links", dangerousLinksFound, dangerousLinksFound > 0 ? "High Attention" : "Clear", !hasScanData, "Total dangerous/critical links found in stored browser scans."),
            Card("scansLast24Hours", "Last 24 Hours", scansLast24Hours, hasScanData ? "Recent" : "No Data", !hasScanData, "Browser plugin scans received in the last 24 hours."),
            Card("scansLast7Days", "Last 7 Days", scansLast7Days, hasScanData ? "Recent" : "No Data", !hasScanData, "Browser plugin scans received in the last 7 days."),
            Card("averageHipScore", "Average HIP Score", averageHipScore, hasScanData ? "Average" : "No Data", !hasScanData, "Average HIP score across stored browser scans."),
            Card("latestScan", "Latest Scan", latestScanUtc is null ? 0 : (int)Math.Max(0, Math.Round((now - latestScanUtc.Value).TotalMinutes)), latestScanUtc is null ? "No Data" : "Minutes Ago", !hasScanData, "Minutes since the latest stored browser scan."),
            Card("riskyFindings", "Risky Findings", riskyFindings, riskyFindings > 0 ? "Needs Review" : "Clear", false, "Risk finding reports with HighRisk, Dangerous, or Critical status."),
            Card("openReviewItems", "Open Review Items", reviews.Count(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo), "Queue", false, "Review items that still need attention."),
            Card("pendingAppeals", "Pending Appeals", appeals.Count(item => item.Status is AppealStatus.Submitted or AppealStatus.InReview or AppealStatus.NeedsMoreInfo), "Queue", false, "Appeals waiting for review or more information."),
            Card("pendingReputationOverrides", "Pending Reputation Overrides", overrides.Count(item => item.Status == OverrideRequestStatus.Pending), "Queue", false, "Manual reputation change requests awaiting approval."),
            Card("activeRules", "Active Rules", rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Active), "Rules", false, "Enabled rules currently enforcing actions."),
            Card("watchModeRules", "Watch Mode Rules", rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Watch), "Rules", false, "Enabled rules observing before enforcement."),
            Card("selfHealingCandidates", "Self-Healing Candidates", candidates.Count, "Candidates", false, "Generated rule candidates available for review."),
            Card("dangerousDomains", "Dangerous Domains", dangerousDomains, dangerousDomains > 0 ? "High Attention" : "Clear", false, "Unique domains with Dangerous or Critical findings."),
            Card("apiHealth", "API Health", 1, "Healthy", false, "Dashboard service responded successfully.")
        };

        var recentScans = browserScans
            .OrderByDescending(scan => scan.LastCheckedUtc)
            .Take(10)
            .Select(scan => new AdminRecentScanItem(
                scan.Domain,
                scan.Score,
                scan.RiskLevel,
                scan.LinksScanned,
                scan.RiskyLinksFound,
                scan.DangerousLinksFound,
                scan.LastCheckedUtc,
                FirstReason(scan)))
            .ToArray();

        var topRiskyDomains = browserScans
            .GroupBy(scan => scan.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var scans = group.ToArray();
                var latest = scans.OrderByDescending(scan => scan.LastCheckedUtc).First();
                return new AdminRiskyDomainItem(
                    group.Key,
                    scans.Sum(scan => scan.RiskyLinksFound),
                    scans.Sum(scan => scan.DangerousLinksFound),
                    (int)Math.Round(scans.Average(scan => scan.Score)),
                    latest.LastCheckedUtc,
                    FirstReason(latest));
            })
            .Where(item => item.RiskyLinksFound > 0 || item.DangerousLinksFound > 0)
            .OrderByDescending(item => item.DangerousLinksFound)
            .ThenByDescending(item => item.RiskyLinksFound)
            .ThenBy(item => item.AverageHipScore)
            .Take(10)
            .ToArray();

        var browserScanActivity = recentScans
            .Select(scan => new AdminRecentActivityItem(
                "Browser Scan",
                "Domain",
                scan.Domain,
                ParseRiskStatus(scan.RiskLevel),
                $"{scan.LinksScanned} links scanned; {scan.RiskyLinksFound} risky links found. {scan.ReasonSummary}",
                scan.LastCheckedUtc));

        var recentActivity = browserScanActivity
            .Concat(findings
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .Take(5)
            .Select(finding => new AdminRecentActivityItem(
                "Risk Finding",
                finding.TargetType.ToString(),
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                finding.DetectedAtUtc)))
            .Concat(reviews
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Review Item",
                    item.TargetType.ToString(),
                    item.TargetId,
                    item.RiskLevel,
                    item.Summary,
                    item.UpdatedAtUtc)))
            .Concat(auditLogs
                .OrderByDescending(item => item.CreatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Audit Log",
                    item.TargetType.ToString(),
                    item.TargetId,
                    null,
                    item.Summary,
                    item.CreatedAtUtc)))
            .Concat(candidates
                .OrderByDescending(item => item.CreatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Generated Rule Candidate",
                    "Rule",
                    item.ProposedRule.RuleId,
                    null,
                    item.CreatedReason,
                    item.CreatedAtUtc)))
            .Concat(overrides
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Reputation Change",
                    item.TargetType.ToString(),
                    item.TargetId,
                    null,
                    $"Requested score change from {item.CurrentScore} to {item.RequestedScore}.",
                    item.UpdatedAtUtc)))
            .OrderByDescending(item => item.CreatedAtUtc)
            .Take(12)
            .ToArray();

        return new AdminDashboardSummary(cards, recentActivity, "Healthy", DateTimeOffset.UtcNow, hasScanData ? "BrowserPluginScanResults" : "NoStoredScanData", hasScanData, topRiskyDomains, recentScans);
    }

    /// <summary>
    /// Determines whether a risk status should count as risky on the dashboard.
    /// </summary>
    /// <param name="status">Risk status.</param>
    /// <returns>True when the status requires review or attention.</returns>
    private static bool IsRisky(RiskStatus status) =>
        status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    /// <summary>
    /// Creates a dashboard metric card.
    /// </summary>
    /// <param name="key">Stable key.</param>
    /// <param name="label">Display label.</param>
    /// <param name="value">Integer value.</param>
    /// <param name="status">Status label.</param>
    /// <param name="isPlaceholder">Whether this is no-data placeholder output.</param>
    /// <param name="description">Privacy-safe description.</param>
    /// <returns>Dashboard card.</returns>
    private static AdminDashboardCard Card(
        string key,
        string label,
        int value,
        string status,
        bool isPlaceholder,
        string description) =>
        new(key, label, value, status, isPlaceholder, description);

    /// <summary>
    /// Selects the first public-safe reason from a stored browser scan.
    /// </summary>
    /// <param name="scan">Stored browser scan result.</param>
    /// <returns>Plain-English reason summary.</returns>
    private static string FirstReason(BrowserScanResultRecord scan) =>
        scan.Reasons.FirstOrDefault(reason => !string.IsNullOrWhiteSpace(reason))
        ?? "Browser plugin scan summary.";

    /// <summary>
    /// Parses stored risk text for recent activity display.
    /// </summary>
    /// <param name="riskLevel">Stored risk level text.</param>
    /// <returns>Risk status or null when the text is not recognized.</returns>
    private static RiskStatus? ParseRiskStatus(string riskLevel) =>
        Enum.TryParse<RiskStatus>(riskLevel, ignoreCase: true, out var status) ? status : null;
}
