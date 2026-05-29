using System.Collections.Concurrent;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Risk;
using HIP.Domain.Review;

namespace HIP.Application.Consumer;

public sealed class ConsumerPortalService(
    IRiskFindingReportRepository riskFindingRepository,
    IAppealService appealService) : IConsumerPortalService
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
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        return findings
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
        var findings = await riskFindingRepository.ListAsync(cancellationToken);
        return findings
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
        var appeals = appealService.List()
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
}
