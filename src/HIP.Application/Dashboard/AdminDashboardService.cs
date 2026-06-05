using HIP.Application.Browser;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.SiteSafety;
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
/// <param name="adminReviewQueueRepository">Generated admin review signal repository.</param>
/// <param name="weightedFeedbackRepository">Weighted feedback repository.</param>
/// <param name="adminSiteSafetyRuleRepository">Admin-managed Site Safety rule repository.</param>
public sealed class AdminDashboardService(
    IBrowserScanResultRepository browserScanResultRepository,
    IRiskFindingReportRepository riskFindingRepository,
    IReviewQueueService reviewQueueService,
    IAppealService appealService,
    IReputationOverrideService reputationOverrideService,
    IAuditLogService auditLogService,
    IRuleRepository ruleRepository,
    IGeneratedRuleCandidateRepository generatedRuleCandidateRepository,
    IAdminReviewQueueRepository adminReviewQueueRepository,
    IWeightedFeedbackRepository weightedFeedbackRepository,
    IAdminSiteSafetyRuleRepository adminSiteSafetyRuleRepository) : IAdminDashboardService
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
        var generatedReviews = await adminReviewQueueRepository.ListAsync(cancellationToken);
        var feedback = await weightedFeedbackRepository.ListAsync(cancellationToken);
        var adminSiteSafetyRules = await adminSiteSafetyRuleRepository.ListAsync(cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var hasScanData = browserScans.Count > 0;
        var totalScans = browserScans.Count;
        var scansToday = browserScans.Count(scan => scan.LastCheckedUtc.UtcDateTime.Date == now.UtcDateTime.Date);
        var domainsScanned = browserScans.Select(scan => scan.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var linksScanned = browserScans.Sum(scan => scan.LinksScanned);
        var riskyLinksFound = browserScans.Sum(scan => scan.RiskyLinksFound);
        var suspiciousLinksFound = browserScans.Sum(scan => scan.SuspiciousLinksFound);
        var dangerousLinksFound = browserScans.Sum(scan => scan.DangerousLinksFound);
        var trustedResults = browserScans.Count(IsTrustedScan);
        var limitedTrustResults = browserScans.Count(IsLimitedTrustScan);
        var suspiciousResults = browserScans.Count(IsSuspiciousScan);
        var highRiskResults = browserScans.Count(IsHighRiskScan);
        var dangerousResults = browserScans.Count(IsDangerousScan);
        var scansLast24Hours = browserScans.Count(scan => scan.LastCheckedUtc >= now.AddHours(-24));
        var scansLast7Days = browserScans.Count(scan => scan.LastCheckedUtc >= now.AddDays(-7));
        var averageHipScore = hasScanData ? (int)Math.Round(browserScans.Average(scan => scan.Score)) : 0;
        var latestScanUtc = browserScans.OrderByDescending(scan => scan.LastCheckedUtc).FirstOrDefault()?.LastCheckedUtc;
        var pendingManualReviews = reviews.Count(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo);
        var pendingGeneratedReviews = generatedReviews.Count(item => item.Status is AdminReviewStatus.Open or AdminReviewStatus.InReview or AdminReviewStatus.Escalated);
        var highSeverityReviews = reviews.Count(item => item.Priority is ReviewPriority.High or ReviewPriority.Critical) +
                                  generatedReviews.Count(item => item.Severity is AdminReviewSeverity.High or AdminReviewSeverity.Critical);
        var oldestOpenReviewUtc = reviews
            .Where(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo)
            .Select(item => item.CreatedAtUtc)
            .Concat(generatedReviews
                .Where(item => item.Status is AdminReviewStatus.Open or AdminReviewStatus.InReview or AdminReviewStatus.Escalated)
                .Select(item => item.CreatedAtUtc))
            .DefaultIfEmpty()
            .Min();
        var oldestOpenReviewAgeHours = oldestOpenReviewUtc == default ? 0 : (int)Math.Max(0, Math.Round((now - oldestOpenReviewUtc).TotalHours));
        var activeTrustRules = rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Active);
        var watchTrustRules = rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Watch);
        var activeBuiltInRules = BuiltInSiteSafetyRules.Create(new SiteSafetyRuleOptions()).Count;
        var activeAdminRules = adminSiteSafetyRules.Count(rule => rule.Status == AdminSiteSafetyRuleStatus.Active && rule.Mode == AdminSiteSafetyRuleMode.Enforced);
        var simulationRules = adminSiteSafetyRules.Count(rule => rule.Mode == AdminSiteSafetyRuleMode.Simulation);
        var watchOnlyRules = adminSiteSafetyRules.Count(rule => rule.Mode == AdminSiteSafetyRuleMode.WatchOnly);
        var disabledRules = rules.Count(rule => !rule.Enabled || rule.Mode == RuleMode.Disabled) +
                            adminSiteSafetyRules.Count(rule => rule.Status is AdminSiteSafetyRuleStatus.Disabled or AdminSiteSafetyRuleStatus.Archived);
        var hasFeedbackData = feedback.Count > 0;
        var suspiciousFeedbackSpikes = CountSuspiciousFeedbackSpikes(feedback);

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
            Card("scansToday", "Scans Today", scansToday, hasScanData ? "Today" : "No Data", !hasScanData, "Stored browser plugin scans received today in UTC."),
            Card("trustedResults", "Trusted Results", trustedResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Trusted status."),
            Card("limitedTrustResults", "Limited Trust Results", limitedTrustResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans where HIP has limited trust data."),
            Card("suspiciousResults", "Suspicious Results", suspiciousResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Suspicious or Caution status."),
            Card("highRiskResults", "High-Risk Results", highRiskResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with HighRisk status."),
            Card("dangerousResults", "Dangerous Results", dangerousResults, hasScanData ? "Real Data" : "No Data", !hasScanData, "Stored scans with Dangerous or Critical status."),
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
            Card("openReviewItems", "Open Review Items", pendingManualReviews, "Queue", false, "Manual review items that still need attention."),
            Card("pendingReviewItems", "Pending Review Items", pendingManualReviews + pendingGeneratedReviews, "Queue", false, "Manual and generated review items that still need attention."),
            Card("highSeverityReviewItems", "High-Severity Reviews", highSeverityReviews, highSeverityReviews > 0 ? "Attention" : "Clear", false, "High or critical manual/generated review items."),
            Card("oldestOpenReviewAgeHours", "Oldest Open Review", oldestOpenReviewAgeHours, oldestOpenReviewAgeHours > 0 ? "Hours" : "No Open Reviews", false, "Age in hours of the oldest open manual or generated review item."),
            Card("pendingAppeals", "Pending Appeals", appeals.Count(item => item.Status is AppealStatus.Submitted or AppealStatus.InReview or AppealStatus.NeedsMoreInfo), "Queue", false, "Appeals waiting for review or more information."),
            Card("pendingReputationOverrides", "Pending Reputation Overrides", overrides.Count(item => item.Status == OverrideRequestStatus.Pending), "Queue", false, "Manual reputation change requests awaiting approval."),
            Card("feedbackReceived", "Feedback Received", feedback.Count, hasFeedbackData ? "Real Data" : "No Data", !hasFeedbackData, "Persisted weighted trust feedback records."),
            Card("looksSafeFeedback", "Looks Safe Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.LooksSafe), hasFeedbackData ? "Real Data" : "No Data", !hasFeedbackData, "Feedback records where users reported the site looked safe."),
            Card("looksSuspiciousFeedback", "Looks Suspicious Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.LooksSuspicious), hasFeedbackData ? "Real Data" : "No Data", !hasFeedbackData, "Feedback records where users reported the site looked suspicious."),
            Card("reportIssueFeedback", "Report Issue Feedback", feedback.Count(item => item.FeedbackType == HipFeedbackType.ReportIssue), hasFeedbackData ? "Real Data" : "No Data", !hasFeedbackData, "Feedback records where users reported an issue."),
            Card("suspiciousFeedbackSpikes", "Suspicious Feedback Spikes", suspiciousFeedbackSpikes, hasFeedbackData ? "Real Data" : "No Data", !hasFeedbackData, "Domains with five or more recent suspicious or issue feedback records."),
            Card("activeRules", "Active Rules", activeTrustRules + activeAdminRules + activeBuiltInRules, "Rules", false, "Built-in, trust, and admin rules currently enforcing behavior."),
            Card("activeBuiltInRules", "Active Built-In Rules", activeBuiltInRules, "Rules", false, "Code-based built-in Site Safety rules."),
            Card("activeAdminRules", "Active Admin Rules", activeAdminRules, "Rules", false, "Admin-created rules currently active or enforced."),
            Card("watchModeRules", "Watch Mode Rules", watchTrustRules, "Rules", false, "Enabled JSON trust rules observing before enforcement."),
            Card("watchOnlyRules", "Watch-Only Rules", watchOnlyRules, "Rules", false, "Admin Site Safety rules in watch-only mode."),
            Card("simulationRules", "Simulation Rules", simulationRules, "Rules", false, "Admin Site Safety rules in simulation mode."),
            Card("disabledRules", "Disabled Rules", disabledRules, "Rules", false, "Disabled trust or admin Site Safety rules."),
            Card("selfHealingCandidates", "Self-Healing Candidates", candidates.Count, "Candidates", false, "Generated rule candidates available for review."),
            Card("dangerousDomains", "Dangerous Domains", dangerousDomains, dangerousDomains > 0 ? "High Attention" : "Clear", false, "Unique domains with Dangerous or Critical findings."),
            Card("externalProviderErrors", "External Provider Errors", 0, "Not connected yet", true, "Provider errors are not persisted for dashboard summaries yet."),
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
            .Concat(generatedReviews
                .OrderByDescending(item => item.UpdatedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Generated Review Signal",
                    item.TargetType.ToString(),
                    item.Domain,
                    ParseRiskStatus(item.CurrentStatus ?? string.Empty),
                    $"{item.ReviewReason}: {item.Summary}",
                    item.UpdatedAtUtc)))
            .Concat(feedback
                .OrderByDescending(item => item.SubmittedAtUtc)
                .Take(5)
                .Select(item => new AdminRecentActivityItem(
                    "Weighted Feedback",
                    "Domain",
                    item.Domain,
                    null,
                    $"Feedback type {item.FeedbackType} from {item.Source}.",
                    item.SubmittedAtUtc)))
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

    /// <summary>
    /// Counts domains with enough suspicious feedback volume to warrant dashboard attention.
    /// This uses only privacy-safe domain and feedback-type fields, never page text or reporter identity.
    /// </summary>
    /// <param name="feedback">Stored weighted feedback submissions.</param>
    /// <returns>Number of domains with suspicious feedback spikes.</returns>
    private static int CountSuspiciousFeedbackSpikes(IReadOnlyCollection<WeightedFeedbackSubmission> feedback) =>
        feedback
            .Where(item => item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue)
            .GroupBy(item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Count(group => group.Count() >= 5);

    /// <summary>
    /// Determines whether a stored scan is Trusted.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label is Trusted.</returns>
    private static bool IsTrustedScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Trusted");

    /// <summary>
    /// Determines whether a stored scan has limited trust data.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates limited trust data.</returns>
    private static bool IsLimitedTrustScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "LimitedTrustData", "LimitedData");

    /// <summary>
    /// Determines whether a stored scan is suspicious or cautionary.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates suspicious/caution risk.</returns>
    private static bool IsSuspiciousScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Suspicious", "Caution");

    /// <summary>
    /// Determines whether a stored scan is high risk.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates high risk.</returns>
    private static bool IsHighRiskScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "HighRisk", "High Risk");

    /// <summary>
    /// Determines whether a stored scan is dangerous or critical.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>True when either risk label or status label indicates dangerous/critical risk.</returns>
    private static bool IsDangerousScan(BrowserScanResultRecord scan) =>
        MatchesScanStatus(scan, "Dangerous", "Critical");

    /// <summary>
    /// Compares both stored status labels so older plugin payloads and newer layered labels remain compatible.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <param name="expectedLabels">Accepted status labels.</param>
    /// <returns>True when the stored status or risk label matches one of the accepted labels.</returns>
    private static bool MatchesScanStatus(BrowserScanResultRecord scan, params string[] expectedLabels)
    {
        var normalizedExpected = expectedLabels.Select(NormalizeStatusLabel).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return normalizedExpected.Contains(NormalizeStatusLabel(scan.Status)) ||
               normalizedExpected.Contains(NormalizeStatusLabel(scan.RiskLevel));
    }

    /// <summary>
    /// Normalizes dashboard status labels by ignoring whitespace and hyphens.
    /// </summary>
    /// <param name="value">Status label.</param>
    /// <returns>Comparable status label.</returns>
    private static string NormalizeStatusLabel(string value) =>
        value.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();
}
