using HIP.Application.Devices;
using HIP.Application.PublicLookup;
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

    public ConsumerAppealSubmissionResult SubmitAppeal(
        string consumerId,
        ConsumerAppealSubmissionRequest request) =>
        SubmitAppealAsync(consumerId, request, CancellationToken.None).GetAwaiter().GetResult();

    public async Task<ConsumerAppealSubmissionResult> SubmitAppealAsync(
        string consumerId,
        ConsumerAppealSubmissionRequest request,
        CancellationToken cancellationToken)
    {
        const int maximumTargetIdLength = 512;
        const int maximumReasonLength = 1000;
        const int maximumEvidenceItems = 8;
        const int maximumEvidenceKeyLength = 64;
        const int maximumEvidenceValueLength = 256;

        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(request.TargetId) || string.IsNullOrWhiteSpace(request.Reason))
        {
            return new ConsumerAppealSubmissionResult(false, string.Empty, request.TargetType, request.TargetId, AppealStatus.Submitted, "Target ID and reason are required.");
        }

        var targetId = request.TargetId.Trim();
        var reason = request.Reason.Trim();
        if (targetId.Length > maximumTargetIdLength || reason.Length > maximumReasonLength)
        {
            return new ConsumerAppealSubmissionResult(false, string.Empty, request.TargetType, targetId, AppealStatus.Submitted, "The appeal target or reason is too long.");
        }

        var suppliedEvidence = request.PrivacySafeEvidence ?? new Dictionary<string, string>();
        if (suppliedEvidence.Count > maximumEvidenceItems ||
            suppliedEvidence.Any(item =>
                string.IsNullOrWhiteSpace(item.Key) ||
                item.Key.Length > maximumEvidenceKeyLength ||
                string.IsNullOrWhiteSpace(item.Value) ||
                item.Value.Length > maximumEvidenceValueLength))
        {
            return new ConsumerAppealSubmissionResult(false, string.Empty, request.TargetType, targetId, AppealStatus.Submitted, "Privacy-safe evidence must be short, named summary values.");
        }

        var privacySafeEvidence = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in suppliedEvidence)
        {
            privacySafeEvidence[item.Key.Trim()] = item.Value.Trim();
        }

        var appeal = await appealService.SubmitAsync(new AppealRequest(
            "",
            request.TargetType,
            targetId,
            ConsumerScopeHash(consumerId),
            reason,
            AppealStatus.Submitted,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null,
            "AutomatedFirstPass",
            "Automated first pass accepted a bounded privacy-safe appeal for human review.",
            privacySafeEvidence), cancellationToken).ConfigureAwait(false);

        return new ConsumerAppealSubmissionResult(true, appeal.AppealId, appeal.TargetType, appeal.TargetId, appeal.Status, "Appeal submitted for HIP review.");
    }

    public async Task<ConsumerSettings> GetSettingsAsync(
        string consumerId,
        CancellationToken cancellationToken)
    {
        var consumerScopeHash = ConsumerScopeHash(consumerId);
        var stored = await settings.GetAsync(consumerScopeHash, cancellationToken).ConfigureAwait(false);
        return NormalizeSettings(stored?.Settings ?? DefaultSettings());
    }

    public async Task<ConsumerSettingsSaveResult> SaveSettingsAsync(
        string consumerId,
        ConsumerSettings requestedSettings,
        CancellationToken cancellationToken)
    {
        if (requestedSettings is null || !SupportedScanModes.Contains(requestedSettings.ScanMode) ||
            !TryNormalizeBadgeConfigurations(requestedSettings.BadgeConfigurations, out var badgeConfigurations))
        {
            return new ConsumerSettingsSaveResult(false, null, "Settings contain an unsupported scan mode or badge configuration.");
        }

        var normalized = requestedSettings with
        {
            ScanMode = NormalizeScanMode(requestedSettings.ScanMode),
            BadgeConfigurations = badgeConfigurations
        };
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

    private static ConsumerSettings NormalizeSettings(ConsumerSettings settings) =>
        TryNormalizeBadgeConfigurations(settings.BadgeConfigurations, out var configurations)
            ? settings with { BadgeConfigurations = configurations }
            : settings with { BadgeConfigurations = new Dictionary<string, ConsumerBadgeConfiguration>(StringComparer.Ordinal) };

    private static bool TryNormalizeBadgeConfigurations(
        IReadOnlyDictionary<string, ConsumerBadgeConfiguration>? requested,
        out IReadOnlyDictionary<string, ConsumerBadgeConfiguration> normalized)
    {
        var result = new Dictionary<string, ConsumerBadgeConfiguration>(StringComparer.Ordinal);
        normalized = result;
        if (requested is null)
        {
            return true;
        }

        if (requested.Count > 50)
        {
            return false;
        }

        foreach (var (domain, configuration) in requested)
        {
            if (configuration is null ||
                configuration.Theme is not ("auto" or "dark" or "light") ||
                configuration.Position is not ("inline" or "top-left" or "top-right" or "bottom-left" or "bottom-right") ||
                configuration.Opacity is < 60 or > 100)
            {
                return false;
            }

            try
            {
                var normalizedDomain = DomainInputValidator.ValidateAndNormalize(domain);
                result[normalizedDomain] = configuration;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        return true;
    }

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
