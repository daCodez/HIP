namespace HIP.Application.SecondLife;

/// <summary>Requests activation of one Second Life HUD using a short-lived setup code.</summary>
public sealed record SecondLifeHudActivationRequest(
    string SetupCode,
    string? HudDeviceId,
    string? AvatarHash,
    string? HudVersion = null)
{
    /// <summary>Compatibility alias used by earlier HUD clients.</summary>
    public string? AvatarIdHash { get; init; }

    /// <summary>Returns the current avatar hash or the compatibility alias when needed.</summary>
    public string? EffectiveAvatarHash => string.IsNullOrWhiteSpace(AvatarHash) ? AvatarIdHash : AvatarHash;
}

/// <summary>Returns the public activation outcome and client configuration.</summary>
public sealed record SecondLifeHudActivationResponse(
    bool Activated,
    string LicenseStatus,
    string Message,
    SecondLifeHudClientConfig ClientConfig,
    string? DeviceId = null,
    DateTimeOffset? ActivatedAtUtc = null,
    string? HudVersion = null,
    string? DeviceCredential = null)
{
    /// <summary>Compatibility alias expected by simple LSL and marketplace activation clients.</summary>
    public SecondLifeHudClientConfig Settings => ClientConfig;
}

/// <summary>Public runtime configuration returned to an activated HUD.</summary>
public sealed record SecondLifeHudClientConfig(
    string Mode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyRoutingEnabled,
    string SafetyPageBaseUrl,
    string ReportFindingUrl);

/// <summary>Requests bounded settings changes for an activated HUD device.</summary>
public sealed record SecondLifeHudSettings(
    string DeviceId,
    string Mode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyRoutingEnabled);

/// <summary>Returns the saved settings outcome without exposing license policy.</summary>
public sealed record SecondLifeHudSettingsResponse(
    bool Saved,
    string Message,
    SecondLifeHudSettings Settings);

/// <summary>Returns the public-safe result of a hosted Second Life scan.</summary>
public sealed record SecondLifeHudScanResponse(
    string RiskLevel,
    int Score,
    IReadOnlyCollection<string> Reasons,
    string RecommendedHudAction,
    string? SafetyPageUrl);
