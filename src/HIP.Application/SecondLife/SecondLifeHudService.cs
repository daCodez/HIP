using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text;
using HIP.Application.Reporting;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SecondLife;

/// <summary>
/// Coordinates Second Life HUD activation, privacy-safe scanning, settings, and finding reports.
/// </summary>
public sealed class SecondLifeHudService : ISecondLifeHudService
{
    private readonly IRiskFindingIngestionService ingestionService;
    private readonly ISetupCodeLicenseService licenseService;
    private readonly IHudDeviceCredentialService credentialService;
    private static readonly ConcurrentDictionary<string, SecondLifeHudSettings> Settings = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> ValidModes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Quiet",
        "Normal",
        "Strict",
        "Paranoid"
    };

    private static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "buff.ly",
        "ow.ly"
    };

    /// <summary>
    /// Creates the HUD service with the configured license manager.
    /// </summary>
    /// <param name="ingestionService">Privacy-safe finding ingestion service.</param>
    /// <param name="licenseService">Setup code license service used for HUD activation and settings.</param>
    /// <param name="credentialService">Issues device-bound credentials after successful activation.</param>
    public SecondLifeHudService(IRiskFindingIngestionService ingestionService, ISetupCodeLicenseService licenseService, IHudDeviceCredentialService credentialService)
    {
        this.ingestionService = ingestionService;
        this.licenseService = licenseService;
        this.credentialService = credentialService;
    }

    /// <inheritdoc />
    public SecondLifeHudActivationResponse Activate(SecondLifeHudActivationRequest request)
    {
        var activation = licenseService.ActivateHud(request.SetupCode, request.HudDeviceId, request.EffectiveAvatarHash, request.HudVersion);
        var config = ToClientConfig(activation.Settings);

        return new SecondLifeHudActivationResponse(
            activation.Activated,
            activation.LicenseStatus.ToString(),
            activation.Message,
            config,
            activation.DeviceId,
            activation.ActivatedAtUtc,
            request.HudVersion,
            activation.Activated && activation.DeviceId is not null ? credentialService.Issue(activation.DeviceId) : null);
    }

    /// <inheritdoc />
    public SecondLifeHudScanResponse Scan(SecondLifeHudScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.DeviceId))
        {
            throw new ArgumentException("HUD device ID is required.");
        }

        if (ContainsPrivateLogMarker(request.MessageText))
        {
            throw new ArgumentException("SL HUD scan accepts only limited suspicious snippets, not full chat logs.");
        }

        var detectedUrls = request.DetectedUrls?.Where(url => !string.IsNullOrWhiteSpace(url)).ToArray() ?? [];
        if (detectedUrls.Length == 0 && string.IsNullOrWhiteSpace(request.MessageText))
        {
            return new SecondLifeHudScanResponse("Low", 88, ["No risky URL signal was supplied."], "StatusOnly", null);
        }

        var text = string.Join(' ', detectedUrls.Append(request.MessageText ?? string.Empty));
        var reasons = new List<string>();

        if (ContainsBrokenUpUrl(text))
        {
            reasons.Add("Broken-up URL detected");
        }

        if (ContainsObfuscatedUrl(text))
        {
            reasons.Add("Obfuscated URL detected");
        }

        if (ContainsShortener(detectedUrls))
        {
            reasons.Add("Shortened link detected");
        }

        if (ContainsRewardBait(text))
        {
            reasons.Add("Suspicious reward wording");
        }

        if (ContainsUrgency(text))
        {
            reasons.Add("Urgency scam wording");
        }

        var critical = text.Contains("critical", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("free-gift.ru", StringComparison.OrdinalIgnoreCase);
        var high = critical || reasons.Count >= 2 || reasons.Any(reason => reason.Contains("Broken-up", StringComparison.OrdinalIgnoreCase));
        var medium = !high && reasons.Count == 1;
        var riskLevel = critical ? "Critical" : high ? "High" : medium ? "Medium" : "Low";
        var score = critical ? 12 : high ? 32 : medium ? 58 : 88;
        var action = riskLevel switch
        {
            "Critical" => "StrongPopupAndSafetyBlock",
            "High" => "PrivateWarningAndPopup",
            "Medium" => "PrivateWarning",
            _ => "StatusOnly"
        };

        if (reasons.Count == 0)
        {
            reasons.Add("No suspicious link pattern detected from privacy-safe HUD inputs.");
        }

        var safetyUrl = riskLevel is "High" or "Critical"
            ? SafetyPageUrl(detectedUrls.FirstOrDefault(), ExtractDomain(detectedUrls.FirstOrDefault()) ?? "unknown", string.Join("; ", reasons))
            : null;

        return new SecondLifeHudScanResponse(riskLevel, score, reasons, action, safetyUrl);
    }

    /// <inheritdoc />
    public SecondLifeHudSettings GetSettings(string deviceId)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        var licenseSettings = licenseService.GetSettingsForDevice(normalizedDeviceId);
        return Settings.GetOrAdd(normalizedDeviceId, id => ToHudSettings(id, licenseSettings));
    }

    /// <inheritdoc />
    public SecondLifeHudSettingsResponse SaveSettings(string deviceId, SecondLifeHudSettings settings)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        if (!ValidModes.Contains(settings.Mode))
        {
            return new SecondLifeHudSettingsResponse(false, "Invalid HUD mode.", GetSettings(normalizedDeviceId));
        }

        var saved = settings with { DeviceId = normalizedDeviceId };
        var licenseSave = licenseService.SaveSettingsForDevice(normalizedDeviceId, ToLicenseSettings(saved));
        if (!licenseSave.Saved)
        {
            return new SecondLifeHudSettingsResponse(false, licenseSave.Message, ToHudSettings(normalizedDeviceId, licenseSave.Settings));
        }

        Settings[normalizedDeviceId] = saved;
        return new SecondLifeHudSettingsResponse(true, licenseSave.Message, saved);
    }

    /// <inheritdoc />
    public async Task<SecondLifeHudFindingResponse> ReportFindingAsync(SecondLifeHudFindingReport report, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(report.Domain) && string.IsNullOrWhiteSpace(report.RiskyUrl))
        {
            return new SecondLifeHudFindingResponse(false, null, string.Empty, report.RiskLevel, false, string.Empty, "Domain or risky URL is required.");
        }

        var domain = NormalizeDomain(report.Domain, report.RiskyUrl);
        var urlHash = string.IsNullOrWhiteSpace(report.UrlHash) && !string.IsNullOrWhiteSpace(report.RiskyUrl)
            ? Sha256(report.RiskyUrl)
            : report.UrlHash;

        var riskReport = new RiskFindingReport(
            "",
            SourceClient.SecondLifeHud,
            ReportPlatform.SecondLife,
            TargetType.Url,
            domain,
            urlHash,
            report.RiskyUrl,
            report.SenderHash,
            report.RiskLevel,
            report.Reason,
            report.DetectedAtUtc == default ? DateTimeOffset.UtcNow : report.DetectedAtUtc,
            ReporterTrustLevel.Medium,
            new PrivacySafeEvidence(
                "second-life-link-risk",
                "Second Life HUD reported a risky link without full chat or IM logs.",
                new Dictionary<string, string>
                {
                    ["hudDeviceId"] = report.HudDeviceId,
                    ["avatarHashPresent"] = (!string.IsNullOrWhiteSpace(report.AvatarHash)).ToString(),
                    ["senderHashPresent"] = (!string.IsNullOrWhiteSpace(report.SenderHash)).ToString()
                }),
            string.IsNullOrWhiteSpace(report.HipSignature) ? "sl-hud-signature-placeholder" : report.HipSignature);

        var response = await ingestionService.IngestAsync(riskReport, cancellationToken);
        return SecondLifeHudFindingResponse.FromIngestion(response, SafetyPageUrl(report.RiskyUrl, domain, report.Reason));
    }

    /// <summary>
    /// Builds the default client config used when no license-specific settings exist.
    /// </summary>
    /// <returns>Default HUD client config.</returns>
    private static SecondLifeHudClientConfig DefaultConfig() =>
        new("Normal", true, true, true, "/safety", "/api/v1/sl-hud/report");

    /// <summary>
    /// Converts license-level settings into the client config returned to LSL scripts.
    /// </summary>
    /// <param name="settings">License settings.</param>
    /// <returns>Client config for the HUD.</returns>
    private static SecondLifeHudClientConfig ToClientConfig(LicenseHudSettings settings) =>
        new(settings.ScanMode, settings.PopupAlertsEnabled, settings.PrivateWarningsEnabled, settings.SafetyPageRoutingEnabled, "/safety", "/api/v1/sl-hud/report");

    /// <summary>
    /// Converts license-level settings into the existing SL HUD settings DTO.
    /// </summary>
    /// <param name="deviceId">HUD device ID.</param>
    /// <param name="settings">License settings.</param>
    /// <returns>HUD settings DTO.</returns>
    private static SecondLifeHudSettings ToHudSettings(string deviceId, LicenseHudSettings settings) =>
        new(deviceId, settings.ScanMode, settings.PopupAlertsEnabled, settings.PrivateWarningsEnabled, settings.SafetyPageRoutingEnabled);

    /// <summary>
    /// Converts the existing SL HUD settings DTO into license-level settings.
    /// </summary>
    /// <param name="settings">HUD settings DTO.</param>
    /// <returns>License settings.</returns>
    private static LicenseHudSettings ToLicenseSettings(SecondLifeHudSettings settings) =>
        new(settings.Mode, settings.PopupAlertsEnabled, settings.PrivateWarningsEnabled, settings.SafetyRoutingEnabled);

    /// <summary>
    /// Creates a HIP safety page URL for risky Second Life links without directly redirecting users.
    /// </summary>
    /// <param name="riskyUrl">Risky URL, when available.</param>
    /// <param name="domain">Detected domain fallback.</param>
    /// <param name="reason">Risk reason to preserve in the safety-page context.</param>
    /// <returns>A relative HIP safety page URL.</returns>
    private static string SafetyPageUrl(string? riskyUrl, string domain, string reason)
    {
        var value = string.IsNullOrWhiteSpace(riskyUrl) ? $"https://{domain}/" : riskyUrl;
        return $"/safety?url={Uri.EscapeDataString(value)}&source=sl-hud&risk={Uri.EscapeDataString(reason)}";
    }

    /// <summary>
    /// Normalizes the domain used in privacy-safe reports.
    /// </summary>
    /// <param name="domain">Domain supplied by the HUD.</param>
    /// <param name="riskyUrl">Risky URL fallback.</param>
    /// <returns>Lowercase normalized domain, or an empty string when unavailable.</returns>
    private static string NormalizeDomain(string domain, string? riskyUrl)
    {
        if (!string.IsNullOrWhiteSpace(domain))
        {
            return domain.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        if (!string.IsNullOrWhiteSpace(riskyUrl) && Uri.TryCreate(riskyUrl, UriKind.Absolute, out var uri))
        {
            return uri.Host.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return string.Empty;
    }

    /// <summary>
    /// Validates and trims a HUD device ID before using it as a settings key.
    /// </summary>
    /// <param name="deviceId">HUD device ID.</param>
    /// <returns>Normalized device ID.</returns>
    private static string NormalizeDeviceId(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            throw new ArgumentException("HUD device ID is required.");
        }

        return deviceId.Trim();
    }

    /// <summary>
    /// Rejects likely full chat/IM logs so the HUD API only accepts limited suspicious snippets.
    /// </summary>
    /// <param name="text">Snippet submitted by the HUD.</param>
    /// <returns>True when the text appears unsafe to ingest.</returns>
    private static bool ContainsPrivateLogMarker(string? text) =>
        !string.IsNullOrWhiteSpace(text) &&
        (text.Contains("private chat log", StringComparison.OrdinalIgnoreCase) ||
         text.Contains("full chat log", StringComparison.OrdinalIgnoreCase) ||
         text.Length > 280);

    /// <summary>
    /// Detects broken-up URL markers commonly used to evade link scanners.
    /// </summary>
    /// <param name="text">Privacy-safe scan text.</param>
    /// <returns>True when a broken-up URL marker is present.</returns>
    private static bool ContainsBrokenUpUrl(string text) =>
        text.Contains(" dot ", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("[dot]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("(dot)", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("hxxps", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("hxxp", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects simple URL obfuscation patterns from HUD inputs.
    /// </summary>
    /// <param name="text">Privacy-safe scan text.</param>
    /// <returns>True when obfuscation is present.</returns>
    private static bool ContainsObfuscatedUrl(string text) =>
        text.Contains("[.]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("://", StringComparison.OrdinalIgnoreCase) && text.Contains(" ", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Checks detected URLs against the local shortener list.
    /// </summary>
    /// <param name="urls">Detected URLs from the HUD.</param>
    /// <returns>True when a known shortener domain is present.</returns>
    private static bool ContainsShortener(IEnumerable<string> urls) =>
        urls.Select(ExtractDomain).Any(domain => domain is not null && ShortenerDomains.Contains(domain));

    /// <summary>
    /// Detects reward/prize wording that often appears in Second Life scam links.
    /// </summary>
    /// <param name="text">Privacy-safe scan text.</param>
    /// <returns>True when reward bait wording is present.</returns>
    private static bool ContainsRewardBait(string text) =>
        text.Contains("reward", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("prize", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("gift", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("claim", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects urgency wording used in social engineering messages.
    /// </summary>
    /// <param name="text">Privacy-safe scan text.</param>
    /// <returns>True when urgency wording is present.</returns>
    private static bool ContainsUrgency(string text) =>
        text.Contains("limited", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("urgent", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("now", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Extracts a normalized domain from a direct or lightly obfuscated URL.
    /// </summary>
    /// <param name="value">URL-like value.</param>
    /// <returns>Normalized domain, or null when parsing fails.</returns>
    private static string? ExtractDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value
            .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
            .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase)
            .Replace(" dot ", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("(dot)", ".", StringComparison.OrdinalIgnoreCase);

        return Uri.TryCreate(normalized, UriKind.Absolute, out var uri)
            ? uri.Host.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase)
            : null;
    }

    /// <summary>
    /// Hashes privacy-sensitive values before storage or reporting.
    /// </summary>
    /// <param name="value">Value to hash.</param>
    /// <returns>SHA-256 hash with an algorithm prefix.</returns>
    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }
}
