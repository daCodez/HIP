using HIP.Domain.Risk;

namespace HIP.Domain.Reporting;

public sealed record PrivacySafeReport(
    string ReportId,
    ReportType ReportType,
    SourceClient Source,
    ReportPlatform Platform,
    string Domain,
    string? RiskyUrl,
    string? UrlHash,
    string? SenderHash,
    string? DeviceHash,
    RiskStatus RiskLevel,
    string ReasonSummary,
    DateTimeOffset ReportedAtUtc,
    ReportStatus Status,
    PrivacySafeEvidence PrivacySafeEvidence,
    string? HipSignature);

public sealed record PrivacySafeReportResponse(
    bool Accepted,
    string? ReportId,
    ReportStatus Status,
    string? NormalizedDomain,
    string? UrlHash,
    string Message);
