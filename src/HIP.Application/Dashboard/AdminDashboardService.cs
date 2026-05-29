using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Dashboard;

public sealed class AdminDashboardService(
    IRiskFindingReportRepository riskFindingRepository,
    IReviewQueueService reviewQueueService,
    IAppealService appealService,
    IReputationOverrideService reputationOverrideService,
    IAuditLogService auditLogService,
    IRuleRepository ruleRepository,
    IGeneratedRuleCandidateRepository generatedRuleCandidateRepository) : IAdminDashboardService
{
    public async Task<AdminDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken)
    {
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        var reviews = reviewQueueService.List();
        var appeals = appealService.List();
        var overrides = reputationOverrideService.List();
        var auditLogs = auditLogService.List();
        var rules = await ruleRepository.ListAsync(cancellationToken);
        var candidates = await generatedRuleCandidateRepository.ListAsync(cancellationToken);

        var riskyFindings = findings.Count(finding => IsRisky(finding.RiskLevel));
        var safetyRoutedLinks = findings.Count(finding => finding.RiskLevel is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical);
        var dangerousDomains = findings
            .Where(finding => finding.RiskLevel is RiskStatus.Dangerous or RiskStatus.Critical)
            .Select(finding => finding.Domain)
            .Where(domain => !string.IsNullOrWhiteSpace(domain))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var cards = new[]
        {
            Card("totalScans", "Total Scans", findings.Count, "Tracking", false, "Privacy-safe finding reports received."),
            Card("riskyFindings", "Risky Findings", riskyFindings, riskyFindings > 0 ? "Needs Review" : "Clear", false, "Findings with HighRisk, Dangerous, or Critical status."),
            Card("safetyRoutedLinks", "Blocked/Routed Safety Links", safetyRoutedLinks, "Estimated", false, "High-risk findings that should route through the safety page."),
            Card("openReviewItems", "Open Review Items", reviews.Count(item => item.Status is ReviewStatus.Open or ReviewStatus.InReview or ReviewStatus.NeedsMoreInfo), "Queue", false, "Review items that still need attention."),
            Card("pendingAppeals", "Pending Appeals", appeals.Count(item => item.Status is AppealStatus.Submitted or AppealStatus.InReview or AppealStatus.NeedsMoreInfo), "Queue", false, "Appeals waiting for review or more information."),
            Card("pendingReputationOverrides", "Pending Reputation Overrides", overrides.Count(item => item.Status == OverrideRequestStatus.Pending), "Queue", false, "Manual reputation change requests awaiting approval."),
            Card("activeRules", "Active Rules", rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Active), "Rules", false, "Enabled rules currently enforcing actions."),
            Card("watchModeRules", "Watch Mode Rules", rules.Count(rule => rule.Enabled && rule.Mode == RuleMode.Watch), "Rules", false, "Enabled rules observing before enforcement."),
            Card("selfHealingCandidates", "Self-Healing Candidates", candidates.Count, "Candidates", false, "Generated rule candidates available for review."),
            Card("dangerousDomains", "Dangerous Domains", dangerousDomains, dangerousDomains > 0 ? "High Attention" : "Clear", false, "Unique domains with Dangerous or Critical findings."),
            Card("apiHealth", "API Health", 1, "Healthy", false, "Dashboard service responded successfully.")
        };

        var recentActivity = findings
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .Take(5)
            .Select(finding => new AdminRecentActivityItem(
                "Risk Finding",
                finding.TargetType.ToString(),
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                finding.DetectedAtUtc))
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

        return new AdminDashboardSummary(cards, recentActivity, "Healthy", DateTimeOffset.UtcNow);
    }

    private static bool IsRisky(RiskStatus status) =>
        status is RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical;

    private static AdminDashboardCard Card(
        string key,
        string label,
        int value,
        string status,
        bool isPlaceholder,
        string description) =>
        new(key, label, value, status, isPlaceholder, description);
}
