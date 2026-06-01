using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text;
using HIP.Application.Reporting;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SecondLife;

public sealed class SecondLifeHudService(IRiskFindingIngestionService ingestionService) : ISecondLifeHudService
{
    private const string ValidDevelopmentSetupCode = "HIP-DEV-SETUP";
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

    public SecondLifeHudActivationResponse Activate(SecondLifeHudActivationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.SetupCode))
        {
            return Inactive("Setup code is required.");
        }

        if (!string.Equals(request.SetupCode.Trim(), ValidDevelopmentSetupCode, StringComparison.Ordinal))
        {
            return Inactive("Setup code was not accepted.");
        }

        var deviceId = string.IsNullOrWhiteSpace(request.HudDeviceId)
            ? $"sl-hud-{Sha256($"{request.SetupCode}:{request.EffectiveAvatarHash}:{request.HudVersion}")[..18].Replace(":", string.Empty, StringComparison.Ordinal)}"
            : request.HudDeviceId.Trim();
        var config = DefaultConfig();
        Settings.TryAdd(deviceId, new SecondLifeHudSettings(
            deviceId,
            config.Mode,
            config.PopupAlertsEnabled,
            config.PrivateWarningsEnabled,
            config.SafetyRoutingEnabled));

        return new SecondLifeHudActivationResponse(
            true,
            "DevelopmentActive",
            "HIP SL HUD activated for development use.",
            config,
            deviceId,
            DateTimeOffset.UtcNow,
            request.HudVersion);
    }

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

    public SecondLifeHudSettings GetSettings(string deviceId)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        return Settings.GetOrAdd(normalizedDeviceId, id => new SecondLifeHudSettings(id, "Normal", true, true, true));
    }

    public SecondLifeHudSettingsResponse SaveSettings(string deviceId, SecondLifeHudSettings settings)
    {
        var normalizedDeviceId = NormalizeDeviceId(deviceId);
        if (!ValidModes.Contains(settings.Mode))
        {
            return new SecondLifeHudSettingsResponse(false, "Invalid HUD mode.", GetSettings(normalizedDeviceId));
        }

        var saved = settings with { DeviceId = normalizedDeviceId };
        Settings[normalizedDeviceId] = saved;
        return new SecondLifeHudSettingsResponse(true, "HUD settings saved.", saved);
    }

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

    private static SecondLifeHudActivationResponse Inactive(string message) =>
        new(false, "Inactive", message, DefaultConfig(), null, null, null);

    private static SecondLifeHudClientConfig DefaultConfig() =>
        new("Normal", true, true, true, "/safety", "/api/v1/sl-hud/report");

    private static string SafetyPageUrl(string? riskyUrl, string domain, string reason)
    {
        var value = string.IsNullOrWhiteSpace(riskyUrl) ? $"https://{domain}/" : riskyUrl;
        return $"/safety?url={Uri.EscapeDataString(value)}&source=sl-hud&risk={Uri.EscapeDataString(reason)}";
    }

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

    private static string NormalizeDeviceId(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            throw new ArgumentException("HUD device ID is required.");
        }

        return deviceId.Trim();
    }

    private static bool ContainsPrivateLogMarker(string? text) =>
        !string.IsNullOrWhiteSpace(text) &&
        (text.Contains("private chat log", StringComparison.OrdinalIgnoreCase) ||
         text.Contains("full chat log", StringComparison.OrdinalIgnoreCase) ||
         text.Length > 280);

    private static bool ContainsBrokenUpUrl(string text) =>
        text.Contains(" dot ", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("[dot]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("(dot)", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("hxxps", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("hxxp", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsObfuscatedUrl(string text) =>
        text.Contains("[.]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("://", StringComparison.OrdinalIgnoreCase) && text.Contains(" ", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsShortener(IEnumerable<string> urls) =>
        urls.Select(ExtractDomain).Any(domain => domain is not null && ShortenerDomains.Contains(domain));

    private static bool ContainsRewardBait(string text) =>
        text.Contains("reward", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("prize", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("gift", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("claim", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsUrgency(string text) =>
        text.Contains("limited", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("urgent", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("now", StringComparison.OrdinalIgnoreCase);

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

    private static string Sha256(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }
}
