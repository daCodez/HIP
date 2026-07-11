using System.Collections.Concurrent;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Risk;
using HIP.Domain.Review;

namespace HIP.Application.Consumer;

public sealed class ConsumerPortalService(
    IRiskFindingReportRepository riskFindingRepository,
    IAppealService appealService,
    IPrivacyHashingService privacyHashingService) : IConsumerPortalService
{
    private static readonly ConcurrentDictionary<string, ConsumerSettings> SettingsByConsumer = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> SupportedScanModes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Quiet",
        "Normal",
        "Strict",
        "Paranoid"
    };

    public Task<ConsumerStatus> GetStatusAsync(string consumerId, CancellationToken cancellationToken) =>
        Task.FromResult(new ConsumerStatus(
            "Active",
            "Development",
            string.IsNullOrWhiteSpace(consumerId) ? "Unknown device" : "Known development device",
            "Consumer portal is an optional MVP. Second Life HUD still works without web login."));

    public async Task<IReadOnlyCollection<ConsumerScanHistoryItem>> GetScansAsync(string consumerId, CancellationToken cancellationToken)
    {
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        return findings
            .Where(finding => string.Equals(finding.ConsumerScopeHash, consumerScopeHash, StringComparison.Ordinal))
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .Select(finding => new ConsumerScanHistoryItem(
                finding.DetectedAtUtc,
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                ActionFor(finding.RiskLevel)))
            .ToArray();
    }

    public async Task<IReadOnlyCollection<ConsumerReportHistoryItem>> GetReportsAsync(string consumerId, CancellationToken cancellationToken)
    {
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        return findings
            .Where(finding => string.Equals(finding.ConsumerScopeHash, consumerScopeHash, StringComparison.Ordinal))
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .Select(finding => new ConsumerReportHistoryItem(
                string.IsNullOrWhiteSpace(finding.ReportId) ? "pending-report-id" : finding.ReportId,
                finding.DetectedAtUtc,
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                ConsumerReportStatus.Submitted))
            .ToArray();
    }

    public Task<IReadOnlyCollection<ConsumerAppealItem>> GetAppealsAsync(string consumerId, CancellationToken cancellationToken)
    {
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        var appeals = appealService.List()
            .Where(appeal => string.Equals(appeal.SubmittedByHash, consumerScopeHash, StringComparison.Ordinal))
            .OrderByDescending(appeal => appeal.UpdatedAtUtc)
            .Select(appeal => new ConsumerAppealItem(
                appeal.AppealId,
                appeal.TargetType,
                appeal.TargetId,
                appeal.Status,
                appeal.UpdatedAtUtc,
                appeal.Reason))
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<ConsumerAppealItem>>(appeals);
    }

    public ConsumerAppealSubmissionResult SubmitAppeal(string consumerId, ConsumerAppealSubmissionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TargetId) || string.IsNullOrWhiteSpace(request.Reason))
        {
            return new ConsumerAppealSubmissionResult(false, string.Empty, request.TargetType, request.TargetId, AppealStatus.Submitted, "Target ID and reason are required.");
        }

        var appeal = appealService.Submit(new AppealRequest(
            "",
            request.TargetType,
            request.TargetId.Trim(),
            ConsumerScopeHash(consumerId),
            request.Reason.Trim(),
            AppealStatus.Submitted,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null,
            "AutomatedFirstPass",
            "MVP automated first pass accepted privacy-safe appeal for human review.",
            request.PrivacySafeEvidence ?? new Dictionary<string, string>()));

        return new ConsumerAppealSubmissionResult(true, appeal.AppealId, appeal.TargetType, appeal.TargetId, appeal.Status, "Appeal submitted for HIP review.");
    }

    public ConsumerSettings GetSettings(string consumerId) =>
        SettingsByConsumer.GetOrAdd(NormalizeConsumerId(consumerId), _ => DefaultSettings());

    public ConsumerSettingsSaveResult SaveSettings(string consumerId, ConsumerSettings settings)
    {
        if (!SupportedScanModes.Contains(settings.ScanMode))
        {
            return new ConsumerSettingsSaveResult(false, null, "Scan mode must be Quiet, Normal, Strict, or Paranoid.");
        }

        var normalized = settings with { ScanMode = NormalizeScanMode(settings.ScanMode) };
        SettingsByConsumer[NormalizeConsumerId(consumerId)] = normalized;
        return new ConsumerSettingsSaveResult(true, normalized, "Settings saved.");
    }

    private static ConsumerSettings DefaultSettings() =>
        new(
            EnablePopupAlerts: true,
            EnablePrivateWarnings: true,
            EnableSafetyPageRouting: true,
            ScanMode: "Normal");

    private static string ActionFor(RiskStatus riskLevel) =>
        riskLevel switch
        {
            RiskStatus.HighRisk or RiskStatus.Dangerous or RiskStatus.Critical => "Routed to safety page",
            RiskStatus.Caution or RiskStatus.Unknown => "Warning shown",
            _ => "Allowed"
        };

    private static string NormalizeConsumerId(string consumerId) =>
        string.IsNullOrWhiteSpace(consumerId) ? "development-consumer" : consumerId.Trim();

    private static string NormalizeScanMode(string scanMode) =>
        SupportedScanModes.Single(mode => string.Equals(mode, scanMode, StringComparison.OrdinalIgnoreCase));

    private string ConsumerScopeHash(string consumerId) =>
        privacyHashingService.Hash(NormalizeConsumerId(consumerId));
}
