using HIP.Domain.Risk;
using HIP.Domain.Review;

namespace HIP.Application.Consumer;

public sealed record ConsumerStatus(
    string ProtectionStatus,
    string LicenseStatus,
    string DeviceStatus,
    string Message);

public sealed record ConsumerScanHistoryItem(
    DateTimeOffset DateUtc,
    string Domain,
    RiskStatus RiskLevel,
    string ReasonSummary,
    string ActionTaken);

public sealed record ConsumerReportHistoryItem(
    string ReportId,
    DateTimeOffset DateUtc,
    string Domain,
    RiskStatus RiskLevel,
    string ReasonSummary,
    ConsumerReportStatus Status);

public sealed record ConsumerAppealItem(
    string AppealId,
    TargetType TargetType,
    string TargetId,
    AppealStatus Status,
    DateTimeOffset UpdatedAtUtc,
    string Summary);

public sealed record ConsumerAppealSubmissionRequest(
    TargetType TargetType,
    string TargetId,
    string Reason,
    IReadOnlyDictionary<string, string>? PrivacySafeEvidence);

public sealed record ConsumerAppealSubmissionResult(
    bool Accepted,
    string AppealId,
    TargetType TargetType,
    string TargetId,
    AppealStatus Status,
    string Message);

public sealed record ConsumerSettings(
    bool EnablePopupAlerts,
    bool EnablePrivateWarnings,
    bool EnableSafetyPageRouting,
    string ScanMode);

public sealed record ConsumerSettingsSaveResult(
    bool Saved,
    ConsumerSettings? Settings,
    string Message);

/// <summary>Owner-hash scoped settings persistence contract; raw consumer IDs are never stored.</summary>
public sealed record ConsumerSettingsRecord(
    string ConsumerScopeHash,
    ConsumerSettings Settings,
    DateTimeOffset UpdatedAtUtc,
    long Version);

public interface IConsumerSettingsRepository
{
    Task<ConsumerSettingsRecord?> GetAsync(
        string consumerScopeHash,
        CancellationToken cancellationToken);

    Task<bool> TrySaveAsync(
        ConsumerSettingsRecord record,
        long expectedVersion,
        CancellationToken cancellationToken);
}

public sealed class InMemoryConsumerSettingsRepository : IConsumerSettingsRepository
{
    private readonly object gate = new();
    private readonly Dictionary<string, ConsumerSettingsRecord> records = new(StringComparer.Ordinal);

    public Task<ConsumerSettingsRecord?> GetAsync(
        string consumerScopeHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            records.TryGetValue(consumerScopeHash, out var record);
            return Task.FromResult(record);
        }
    }

    public Task<bool> TrySaveAsync(
        ConsumerSettingsRecord record,
        long expectedVersion,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            records.TryGetValue(record.ConsumerScopeHash, out var existing);
            var currentVersion = existing?.Version ?? 0;
            if (currentVersion != expectedVersion || record.Version != expectedVersion + 1)
            {
                return Task.FromResult(false);
            }

            records[record.ConsumerScopeHash] = record;
            return Task.FromResult(true);
        }
    }
}

public enum ConsumerReportStatus
{
    Submitted,
    InReview,
    Confirmed,
    Rejected,
    NeedsMoreInfo,
    Closed
}
