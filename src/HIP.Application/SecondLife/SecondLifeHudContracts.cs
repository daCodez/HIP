using HIP.Application.Reporting;
using HIP.Domain.Risk;

namespace HIP.Application.SecondLife;

public sealed record SecondLifeHudActivationRequest(
    string SetupCode,
    string HudDeviceId,
    string? AvatarHash);

public sealed record SecondLifeHudActivationResponse(
    bool Activated,
    string LicenseStatus,
    string Message,
    SecondLifeHudClientConfig ClientConfig);

public sealed record SecondLifeHudClientConfig(
    string Mode,
    bool PopupAlertsEnabled,
    string SafetyPageBaseUrl,
    string ReportFindingUrl);

public sealed record SecondLifeHudFindingReport(
    string HudDeviceId,
    string? AvatarHash,
    string Domain,
    string? RiskyUrl,
    string? UrlHash,
    string? SenderHash,
    RiskStatus RiskLevel,
    string Reason,
    DateTimeOffset DetectedAtUtc,
    string HipSignature);

public sealed record SecondLifeHudFindingResponse(
    bool Accepted,
    string? ReportId,
    string Domain,
    RiskStatus RiskLevel,
    bool ReviewCreated,
    string SafetyPageUrl,
    string Message)
{
    public static SecondLifeHudFindingResponse FromIngestion(RiskFindingIngestionResponse response, string safetyPageUrl) =>
        new(
            response.Accepted,
            response.ReportId,
            response.NormalizedDomain ?? string.Empty,
            response.RiskLevel,
            response.ReviewCreated,
            safetyPageUrl,
            response.Message);
}
