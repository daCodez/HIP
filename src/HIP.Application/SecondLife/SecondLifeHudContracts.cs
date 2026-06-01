using HIP.Application.Reporting;
using HIP.Domain.Risk;

namespace HIP.Application.SecondLife;

public sealed record SecondLifeHudActivationRequest(
    string SetupCode,
    string? HudDeviceId,
    string? AvatarHash,
    string? HudVersion = null)
{
    public string? AvatarIdHash { get; init; }

    public string? EffectiveAvatarHash => string.IsNullOrWhiteSpace(AvatarHash) ? AvatarIdHash : AvatarHash;
}

public sealed record SecondLifeHudActivationResponse(
    bool Activated,
    string LicenseStatus,
    string Message,
    SecondLifeHudClientConfig ClientConfig,
    string? DeviceId = null,
    DateTimeOffset? ActivatedAtUtc = null,
    string? HudVersion = null)
{
    /// <summary>
    /// Provides the same HUD settings under the property name expected by simple LSL and marketplace activation clients.
    /// </summary>
    public SecondLifeHudClientConfig Settings => ClientConfig;
}

public sealed record SecondLifeHudClientConfig(
    string Mode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyRoutingEnabled,
    string SafetyPageBaseUrl,
    string ReportFindingUrl);

public sealed record SecondLifeHudSettings(
    string DeviceId,
    string Mode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyRoutingEnabled);

public sealed record SecondLifeHudSettingsResponse(
    bool Saved,
    string Message,
    SecondLifeHudSettings Settings);

public sealed record SecondLifeHudScanRequest(
    string DeviceId,
    string Source,
    string? MessageText,
    IReadOnlyCollection<string> DetectedUrls,
    string? SenderHash);

public sealed record SecondLifeHudScanResponse(
    string RiskLevel,
    int Score,
    IReadOnlyCollection<string> Reasons,
    string RecommendedHudAction,
    string? SafetyPageUrl);

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
