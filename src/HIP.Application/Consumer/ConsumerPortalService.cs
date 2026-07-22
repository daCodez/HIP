using HIP.Application.Devices;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Devices;
using HIP.Domain.Risk;
using HIP.Domain.Review;
using Microsoft.Extensions.Logging;

namespace HIP.Application.Consumer;

public sealed class ConsumerPortalService(
    IRiskFindingReportRepository riskFindingRepository,
    IAppealService appealService,
    IPrivacyHashingService privacyHashingService,
    IDeviceRegistrationService deviceRegistrationService,
    IAppealRepository appealRepository,
    ILogger<ConsumerPortalService>? logger = null,
    IConsumerSettingsRepository? settingsRepository = null,
    TimeProvider? timeProvider = null) : IConsumerPortalService
{
    private const int MaximumHistoryItems = 100;
    private const int MaximumSettingsSaveAttempts = 3;
    private readonly IConsumerSettingsRepository settings =
        settingsRepository ?? new InMemoryConsumerSettingsRepository();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private static readonly HashSet<string> SupportedScanModes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Quiet",
        "Normal",
        "Strict",
        "Paranoid"
    };

    public async Task<ConsumerStatus> GetStatusAsync(string consumerId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(consumerId))
        {
            return new ConsumerStatus(
                "Unknown",
                "Not linked",
                "Device status unavailable",
                "HIP could not bind device status to a consumer account.");
        }

        IReadOnlyCollection<DeviceRegistrationDeviceResponse> devices;
        try
        {
            devices = await deviceRegistrationService.ListAsync(consumerId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger?.LogWarning(
                "Consumer device status lookup failed with {FailureType}.",
                exception.GetType().Name);
            return new ConsumerStatus(
                "Unavailable",
                "Not linked",
                "Device status unavailable",
                "Device registration status is temporarily unavailable. Try again shortly.");
        }

        var activeDevices = devices.Count(device => device.RevocationState == DeviceRevocationState.Active);
        var revokedDevices = devices.Count - activeDevices;
        var deviceStatus = activeDevices switch
        {
            0 when revokedDevices == 0 => "No registered devices",
            0 => $"No active devices · {revokedDevices} revoked",
            1 => revokedDevices == 0 ? "1 active device" : $"1 active device · {revokedDevices} revoked",
            _ => revokedDevices == 0
                ? $"{activeDevices} active devices"
                : $"{activeDevices} active devices · {revokedDevices} revoked"
        };

        return new ConsumerStatus(
            "Active",
            "Not linked",
            deviceStatus,
            "Device status is derived from proof-of-possession registrations owned by this consumer account.");
    }

    public async Task<IReadOnlyCollection<ConsumerScanHistoryItem>> GetScansAsync(string consumerId, CancellationToken cancellationToken)
    {
        var consumerScopeHashes = ConsumerScopeHashes(consumerId);
        var findings = await riskFindingRepository.ListByConsumerScopeHashesAsync(
            consumerScopeHashes,
            MaximumHistoryItems,
            cancellationToken).ConfigureAwait(false);
        return findings
            .Where(finding =>
                finding.ConsumerScopeHash is not null &&
                consumerScopeHashes.Contains(finding.ConsumerScopeHash))
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .ThenBy(finding => finding.ReportId, StringComparer.Ordinal)
            .Take(MaximumHistoryItems)
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
        var consumerScopeHashes = ConsumerScopeHashes(consumerId);
        var findings = await riskFindingRepository.ListByConsumerScopeHashesAsync(
            consumerScopeHashes,
            MaximumHistoryItems,
            cancellationToken).ConfigureAwait(false);
        return findings
            .Where(finding =>
                finding.ConsumerScopeHash is not null &&
                consumerScopeHashes.Contains(finding.ConsumerScopeHash))
            .OrderByDescending(finding => finding.DetectedAtUtc)
            .ThenBy(finding => finding.ReportId, StringComparer.Ordinal)
            .Take(MaximumHistoryItems)
            .Select(finding => new ConsumerReportHistoryItem(
                string.IsNullOrWhiteSpace(finding.ReportId) ? "pending-report-id" : finding.ReportId,
                finding.DetectedAtUtc,
                finding.Domain,
                finding.RiskLevel,
                finding.Reason,
                ConsumerReportStatus.Submitted))
            .ToArray();
    }

    public async Task<IReadOnlyCollection<ConsumerAppealItem>> GetAppealsAsync(
        string consumerId,
        CancellationToken cancellationToken)
    {
        var consumerScopeHashes = ConsumerScopeHashes(consumerId);
        var storedAppeals = await appealRepository.ListBySubmitterHashesAsync(
            consumerScopeHashes,
            MaximumHistoryItems,
            cancellationToken).ConfigureAwait(false);
        return storedAppeals
            .Where(appeal => consumerScopeHashes.Contains(appeal.SubmittedByHash))
            .OrderByDescending(appeal => appeal.UpdatedAtUtc)
            .ThenBy(appeal => appeal.AppealId, StringComparer.Ordinal)
            .Take(MaximumHistoryItems)
            .Select(appeal => new ConsumerAppealItem(
                appeal.AppealId,
                appeal.TargetType,
                appeal.TargetId,
                appeal.Status,
                appeal.UpdatedAtUtc,
                appeal.Reason))
            .ToArray();
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

    public async Task<ConsumerSettings> GetSettingsAsync(
        string consumerId,
        CancellationToken cancellationToken)
    {
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        var stored = await settings.GetAsync(consumerScopeHash, cancellationToken).ConfigureAwait(false);
        return stored?.Settings ?? DefaultSettings();
    }

    public async Task<ConsumerSettingsSaveResult> SaveSettingsAsync(
        string consumerId,
        ConsumerSettings requestedSettings,
        CancellationToken cancellationToken)
    {
        if (requestedSettings is null || !SupportedScanModes.Contains(requestedSettings.ScanMode))
        {
            return new ConsumerSettingsSaveResult(false, null, "Scan mode must be Quiet, Normal, Strict, or Paranoid.");
        }

        var normalized = requestedSettings with { ScanMode = NormalizeScanMode(requestedSettings.ScanMode) };
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        for (var attempt = 0; attempt < MaximumSettingsSaveAttempts; attempt++)
        {
            var current = await settings.GetAsync(consumerScopeHash, cancellationToken).ConfigureAwait(false);
            var expectedVersion = current?.Version ?? 0;
            var record = new ConsumerSettingsRecord(
                consumerScopeHash,
                normalized,
                clock.GetUtcNow(),
                expectedVersion + 1);
            if (await settings.TrySaveAsync(record, expectedVersion, cancellationToken).ConfigureAwait(false))
            {
                return new ConsumerSettingsSaveResult(true, normalized, "Settings saved.");
            }
        }

        return new ConsumerSettingsSaveResult(
            false,
            null,
            "Settings changed concurrently. Reload and try again.");
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

    private IReadOnlyCollection<string> ConsumerScopeHashes(string consumerId) =>
        privacyHashingService
            .HashCandidates(NormalizeConsumerId(consumerId))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
}
