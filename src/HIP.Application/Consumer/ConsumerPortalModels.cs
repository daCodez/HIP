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

public sealed record ConsumerSettings(
    bool EnablePopupAlerts,
    bool EnablePrivateWarnings,
    bool EnableSafetyPageRouting,
    string ScanMode);

public sealed record ConsumerSettingsSaveResult(
    bool Saved,
    ConsumerSettings? Settings,
    string Message);

public enum ConsumerReportStatus
{
    Submitted,
    InReview,
    Confirmed,
    Rejected,
    NeedsMoreInfo,
    Closed
}
