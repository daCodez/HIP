using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace HIP.Application.SecondLife;

/// <summary>
/// Identifies where a simulated Second Life message came from.
/// </summary>
public enum SecondLifeHudSimulationSourceType
{
    /// <summary>
    /// Nearby chat visible to the HUD listener.
    /// </summary>
    LocalChat,

    /// <summary>
    /// Group chat input represented as privacy-safe simulator data.
    /// </summary>
    GroupChat,

    /// <summary>
    /// Private IM input represented as opt-in privacy-safe simulator data.
    /// </summary>
    PrivateIM,

    /// <summary>
    /// Message sent by an in-world object.
    /// </summary>
    ObjectMessage,

    /// <summary>
    /// Manual test case entered in the web simulator.
    /// </summary>
    ManualTest
}

/// <summary>
/// Recommended HUD action produced by the simulator.
/// </summary>
public enum SecondLifeHudRecommendedAction
{
    /// <summary>
    /// No warning or status change is needed.
    /// </summary>
    NoAction,

    /// <summary>
    /// Update HUD status only without interrupting the owner.
    /// </summary>
    HudStatusOnly,

    /// <summary>
    /// Send an owner-only private warning.
    /// </summary>
    PrivateWarning,

    /// <summary>
    /// Send an owner-only private warning and show an optional popup.
    /// </summary>
    PrivateWarningAndPopup,

    /// <summary>
    /// Warn and route the owner through the HIP safety page.
    /// </summary>
    SafetyPageWarning,

    /// <summary>
    /// Strong critical warning where the safety page should not allow normal continue flow by default.
    /// </summary>
    CriticalBlockWarning
}

/// <summary>
/// Input for the SL HUD simulator. It intentionally separates message text from the privacy-safe payload preview.
/// </summary>
/// <param name="Sender">Sender display name or hash used only for preview text.</param>
/// <param name="MessageText">Message text entered for simulation.</param>
/// <param name="SourceType">Source type for simulated platform context.</param>
/// <param name="DetectedUrls">Optional URLs supplied by a test harness or HUD parser.</param>
/// <param name="ScanMode">HUD scan mode.</param>
/// <param name="PopupAlertsEnabled">Whether popup alerts are enabled.</param>
/// <param name="PrivateWarningsEnabled">Whether owner warnings are enabled.</param>
/// <param name="SafetyPageRoutingEnabled">Whether safety-page routing is enabled.</param>
public sealed record SecondLifeHudSimulationRequest(
    string? Sender,
    string? MessageText,
    SecondLifeHudSimulationSourceType SourceType,
    IReadOnlyCollection<string>? DetectedUrls,
    string ScanMode,
    bool PopupAlertsEnabled,
    bool PrivateWarningsEnabled,
    bool SafetyPageRoutingEnabled);

/// <summary>
/// Result returned by the simulator for UI, API, and automated tests.
/// </summary>
/// <param name="DetectedUrls">URLs found or reconstructed by the simulator.</param>
/// <param name="RiskLevel">Risk level label.</param>
/// <param name="Score">HIP-style score from 0 to 100.</param>
/// <param name="Reasons">Plain-English reasons.</param>
/// <param name="RecommendedHudAction">Recommended HUD behavior.</param>
/// <param name="OwnerWarningWouldShow">Whether an owner-only warning would show.</param>
/// <param name="PopupWouldShow">Whether a popup would show.</param>
/// <param name="SafetyPageWouldBeUsed">Whether the HIP safety page would be used.</param>
/// <param name="SafetyPageUrl">Safety page URL preview.</param>
/// <param name="PrivacySafePayload">Payload preview that excludes full private text.</param>
/// <param name="RawPrivateTextExcluded">Confirms the payload omits full message/private text.</param>
/// <param name="OwnerWarningPreview">Owner warning text preview.</param>
/// <param name="PopupPreview">Popup text preview.</param>
public sealed record SecondLifeHudSimulationResult(
    IReadOnlyCollection<string> DetectedUrls,
    string RiskLevel,
    int Score,
    IReadOnlyCollection<string> Reasons,
    SecondLifeHudRecommendedAction RecommendedHudAction,
    bool OwnerWarningWouldShow,
    bool PopupWouldShow,
    bool SafetyPageWouldBeUsed,
    string? SafetyPageUrl,
    IReadOnlyDictionary<string, string> PrivacySafePayload,
    bool RawPrivateTextExcluded,
    string? OwnerWarningPreview,
    string? PopupPreview);

/// <summary>
/// Simulates HUD behavior so alert and privacy behavior can be tested outside Second Life.
/// </summary>
public interface ISecondLifeHudSimulationService
{
    /// <summary>
    /// Runs the simulator for one message.
    /// </summary>
    /// <param name="request">Simulation input.</param>
    /// <returns>Simulation output with risk, alert behavior, and payload preview.</returns>
    SecondLifeHudSimulationResult Simulate(SecondLifeHudSimulationRequest request);
}

/// <summary>
/// MVP simulator for Second Life HUD behavior. It mirrors the current LSL/client contract without requiring Second Life.
/// </summary>
public sealed partial class SecondLifeHudSimulationService : ISecondLifeHudSimulationService
{
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

    /// <inheritdoc />
    public SecondLifeHudSimulationResult Simulate(SecondLifeHudSimulationRequest request)
    {
        Validate(request);

        var message = request.MessageText ?? string.Empty;
        var detectedUrls = DetectUrls(message, request.DetectedUrls).ToArray();
        var reasons = DetectReasons(message, detectedUrls, request.Sender).ToList();
        var risk = CalculateRisk(message, reasons);
        var score = ScoreForRisk(risk);
        var modeAllowsOwnerWarning = ModeAllowsAlert(request.ScanMode, risk);
        var ownerWarning = request.PrivateWarningsEnabled && modeAllowsOwnerWarning && risk is not "Safe";
        var popup = ownerWarning && request.PopupAlertsEnabled && risk is "High" or "Critical";
        var safety = request.SafetyPageRoutingEnabled && risk is "High" or "Critical";
        var safetyUrl = safety ? BuildSafetyPageUrl(detectedUrls.FirstOrDefault(), reasons) : null;
        var action = ChooseAction(risk, ownerWarning, popup, safety, modeAllowsOwnerWarning);
        var payload = BuildPrivacySafePayload(request, detectedUrls, reasons, risk);
        var sender = string.IsNullOrWhiteSpace(request.Sender) ? "unknown sender" : request.Sender.Trim();

        return new SecondLifeHudSimulationResult(
            detectedUrls,
            risk,
            score,
            reasons.Count == 0 ? ["No risky link signal detected."] : reasons,
            action,
            ownerWarning,
            popup,
            safety,
            safetyUrl,
            payload,
            !payload.ContainsKey("messageText") && !payload.ContainsKey("privateChatLog"),
            ownerWarning ? $"HIP Warning: Message from {sender} looks suspicious." : null,
            popup ? $"{risk} link detected. Use the HIP safety page before opening." : null);
    }

    /// <summary>
    /// Validates simulator input before any scoring logic runs.
    /// </summary>
    /// <param name="request">Simulation request.</param>
    private static void Validate(SecondLifeHudSimulationRequest request)
    {
        if (!Enum.IsDefined(request.SourceType))
        {
            throw new ArgumentException("Invalid SL HUD source type.");
        }

        if (!ValidModes.Contains(request.ScanMode))
        {
            throw new ArgumentException("Invalid scan mode.");
        }
    }

    /// <summary>
    /// Detects direct and obfuscated URLs from a simulated message.
    /// </summary>
    /// <param name="message">Message text used only inside the simulator.</param>
    /// <param name="providedUrls">Optional URLs supplied by the test harness.</param>
    /// <returns>Detected or reconstructed URL list.</returns>
    private static IReadOnlyCollection<string> DetectUrls(string message, IReadOnlyCollection<string>? providedUrls)
    {
        var urls = new List<string>();
        if (providedUrls is not null)
        {
            urls.AddRange(providedUrls.Where(url => !string.IsNullOrWhiteSpace(url)).Select(NormalizeUrl));
        }

        foreach (Match match in UrlRegex().Matches(message))
        {
            urls.Add(NormalizeUrl(match.Value));
        }

        if (ContainsBrokenUpUrl(message))
        {
            var reconstructed = ReconstructBrokenUpUrl(message);
            if (!string.IsNullOrWhiteSpace(reconstructed))
            {
                urls.Add(reconstructed);
            }
        }

        return urls.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>
    /// Builds plain-English reasons from simulated signals.
    /// </summary>
    /// <param name="message">Message text used only inside the simulator.</param>
    /// <param name="detectedUrls">Detected URLs.</param>
    /// <param name="sender">Sender preview value.</param>
    /// <returns>Reason list.</returns>
    private static IReadOnlyCollection<string> DetectReasons(string message, IReadOnlyCollection<string> detectedUrls, string? sender)
    {
        var reasons = new List<string>();

        if (detectedUrls.Count > 0)
        {
            reasons.Add("URL detected for HIP scan.");
        }

        if (ContainsShortener(detectedUrls))
        {
            reasons.Add("Shortened URL detected.");
        }

        if (ContainsBrokenUpUrl(message))
        {
            reasons.Add("Broken-up URL detected.");
        }

        if (ContainsObfuscatedUrl(message))
        {
            reasons.Add("Obfuscated hxxp URL detected.");
        }

        if (ContainsRewardBait(message))
        {
            reasons.Add("Reward bait wording detected.");
        }

        if (ContainsUrgency(message))
        {
            reasons.Add("Urgency scam wording detected.");
        }

        if (!string.IsNullOrWhiteSpace(sender) && sender.Contains("low", StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add("Low-reputation sender signal.");
        }

        return reasons;
    }

    /// <summary>
    /// Converts reasons into a simple MVP risk level.
    /// </summary>
    /// <param name="message">Message text used only for critical keyword checks.</param>
    /// <param name="reasons">Detected reasons.</param>
    /// <returns>Risk level label.</returns>
    private static string CalculateRisk(string message, IReadOnlyCollection<string> reasons)
    {
        if (message.Contains("critical", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("malware", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("free-gift.ru", StringComparison.OrdinalIgnoreCase))
        {
            return "Critical";
        }

        if (reasons.Any(reason => reason.Contains("Broken-up", StringComparison.OrdinalIgnoreCase) ||
                                  reason.Contains("Obfuscated", StringComparison.OrdinalIgnoreCase)) ||
            reasons.Count(reason => !reason.Contains("URL detected", StringComparison.OrdinalIgnoreCase)) >= 2)
        {
            return "High";
        }

        if (reasons.Any(reason => reason.Contains("Shortened", StringComparison.OrdinalIgnoreCase) ||
                                  reason.Contains("Reward", StringComparison.OrdinalIgnoreCase) ||
                                  reason.Contains("Urgency", StringComparison.OrdinalIgnoreCase) ||
                                  reason.Contains("Low-reputation", StringComparison.OrdinalIgnoreCase)))
        {
            return "Medium";
        }

        return reasons.Count == 0 ? "Safe" : "Low";
    }

    /// <summary>
    /// Maps simulator risk to a HIP-style 0-100 score.
    /// </summary>
    /// <param name="risk">Risk level.</param>
    /// <returns>Score value.</returns>
    private static int ScoreForRisk(string risk) =>
        risk switch
        {
            "Critical" => 10,
            "High" => 32,
            "Medium" => 58,
            "Low" => 74,
            _ => 90
        };

    /// <summary>
    /// Applies MVP scan-mode suppression rules.
    /// </summary>
    /// <param name="mode">Scan mode.</param>
    /// <param name="risk">Risk level.</param>
    /// <returns>True when alerts should show for the risk level.</returns>
    private static bool ModeAllowsAlert(string mode, string risk) =>
        mode switch
        {
            "Quiet" => risk is "High" or "Critical",
            "Normal" => risk is "Medium" or "High" or "Critical",
            "Strict" => risk is "Low" or "Medium" or "High" or "Critical",
            "Paranoid" => risk is not "Safe",
            _ => false
        };

    /// <summary>
    /// Chooses the HUD action from risk level and alert settings.
    /// </summary>
    /// <param name="risk">Risk level.</param>
    /// <param name="ownerWarning">Whether owner warning would show.</param>
    /// <param name="popup">Whether popup would show.</param>
    /// <param name="safety">Whether safety routing would be used.</param>
    /// <param name="modeAllowsOwnerWarning">Whether mode allows an alert for this risk.</param>
    /// <returns>Recommended HUD action.</returns>
    private static SecondLifeHudRecommendedAction ChooseAction(string risk, bool ownerWarning, bool popup, bool safety, bool modeAllowsOwnerWarning)
    {
        if (risk == "Safe")
        {
            return SecondLifeHudRecommendedAction.NoAction;
        }

        if (!modeAllowsOwnerWarning)
        {
            return SecondLifeHudRecommendedAction.HudStatusOnly;
        }

        if (risk == "Critical")
        {
            return SecondLifeHudRecommendedAction.CriticalBlockWarning;
        }

        if (safety)
        {
            return SecondLifeHudRecommendedAction.SafetyPageWarning;
        }

        if (popup)
        {
            return SecondLifeHudRecommendedAction.PrivateWarningAndPopup;
        }

        return ownerWarning ? SecondLifeHudRecommendedAction.PrivateWarning : SecondLifeHudRecommendedAction.HudStatusOnly;
    }

    /// <summary>
    /// Builds a privacy-safe payload preview that excludes full private text.
    /// </summary>
    /// <param name="request">Simulation request.</param>
    /// <param name="detectedUrls">Detected URLs.</param>
    /// <param name="reasons">Risk reasons.</param>
    /// <param name="risk">Risk level.</param>
    /// <returns>Payload preview dictionary.</returns>
    private static IReadOnlyDictionary<string, string> BuildPrivacySafePayload(
        SecondLifeHudSimulationRequest request,
        IReadOnlyCollection<string> detectedUrls,
        IReadOnlyCollection<string> reasons,
        string risk)
    {
        if (risk == "Safe")
        {
            return new Dictionary<string, string>
            {
                ["source"] = request.SourceType.ToString(),
                ["sentToHip"] = "false"
            };
        }

        var riskyUrl = detectedUrls.FirstOrDefault() ?? string.Empty;
        var payload = new Dictionary<string, string>
        {
            ["sourceClient"] = "SecondLifeHud",
            ["platform"] = "SecondLife",
            ["source"] = request.SourceType.ToString(),
            ["riskLevel"] = risk,
            ["riskReason"] = string.Join("; ", reasons),
            ["timestampUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["senderHash"] = Hash(request.Sender ?? "unknown")
        };

        if (!string.IsNullOrWhiteSpace(riskyUrl))
        {
            payload["riskyUrl"] = riskyUrl;
            payload["urlHash"] = Hash(riskyUrl);
            payload["domain"] = ExtractDomain(riskyUrl) ?? "unknown";
        }

        if (ShouldIncludeLimitedSnippet(request.SourceType, reasons))
        {
            payload["limitedSuspiciousSnippet"] = LimitSnippet(request.MessageText ?? string.Empty);
        }

        return payload;
    }

    /// <summary>
    /// Determines whether a limited snippet is useful enough to include in the privacy-safe payload preview.
    /// </summary>
    /// <param name="sourceType">Message source type.</param>
    /// <param name="reasons">Detected reasons.</param>
    /// <returns>True when a limited snippet is included.</returns>
    private static bool ShouldIncludeLimitedSnippet(SecondLifeHudSimulationSourceType sourceType, IReadOnlyCollection<string> reasons) =>
        sourceType is not SecondLifeHudSimulationSourceType.PrivateIM &&
        reasons.Any(reason => reason.Contains("Reward", StringComparison.OrdinalIgnoreCase) ||
                              reason.Contains("Urgency", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Limits suspicious snippets so simulation output does not normalize full chat logging.
    /// </summary>
    /// <param name="message">Message text.</param>
    /// <returns>Short snippet.</returns>
    private static string LimitSnippet(string message) =>
        message.Length <= 120 ? message : message[..120];

    /// <summary>
    /// Creates a relative HIP safety page URL for simulated risky links.
    /// </summary>
    /// <param name="url">Risky URL.</param>
    /// <param name="reasons">Risk reasons.</param>
    /// <returns>Safety page URL.</returns>
    private static string BuildSafetyPageUrl(string? url, IReadOnlyCollection<string> reasons)
    {
        var value = string.IsNullOrWhiteSpace(url) ? "https://unknown/" : url;
        return $"/safety?url={Uri.EscapeDataString(value)}&source=sl-hud&risk={Uri.EscapeDataString(string.Join("; ", reasons))}";
    }

    /// <summary>
    /// Detects known URL shortener domains.
    /// </summary>
    /// <param name="urls">Detected URLs.</param>
    /// <returns>True when a known shortener is present.</returns>
    private static bool ContainsShortener(IEnumerable<string> urls) =>
        urls.Select(ExtractDomain).Any(domain => domain is not null && ShortenerDomains.Contains(domain));

    /// <summary>
    /// Detects broken-up URL markers used to evade scanners.
    /// </summary>
    /// <param name="text">Message text.</param>
    /// <returns>True when broken-up URL markers are present.</returns>
    private static bool ContainsBrokenUpUrl(string text) =>
        text.Contains(" dot ", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("[dot]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("(dot)", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects hxxp and bracket-dot obfuscation.
    /// </summary>
    /// <param name="text">Message text.</param>
    /// <returns>True when obfuscation is present.</returns>
    private static bool ContainsObfuscatedUrl(string text) =>
        text.Contains("hxxp", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("[.]", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("(.)", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects reward bait language.
    /// </summary>
    /// <param name="text">Message text.</param>
    /// <returns>True when reward bait appears.</returns>
    private static bool ContainsRewardBait(string text) =>
        text.Contains("reward", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("prize", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("gift", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("claim", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects urgency wording used in scams.
    /// </summary>
    /// <param name="text">Message text.</param>
    /// <returns>True when urgency appears.</returns>
    private static bool ContainsUrgency(string text) =>
        text.Contains("urgent", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("limited", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("now", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reconstructs simple broken-up URL text into an URL-like value for the safety page.
    /// </summary>
    /// <param name="text">Message text.</param>
    /// <returns>Reconstructed URL or an empty string.</returns>
    private static string ReconstructBrokenUpUrl(string text)
    {
        var normalized = NormalizeUrl(text);
        var match = UrlRegex().Match(normalized);
        return match.Success ? match.Value : string.Empty;
    }

    /// <summary>
    /// Normalizes common URL obfuscation markers.
    /// </summary>
    /// <param name="value">URL or message fragment.</param>
    /// <returns>Normalized text.</returns>
    private static string NormalizeUrl(string value) =>
        value.Trim()
            .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase)
            .Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase)
            .Replace(" dot ", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("(dot)", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("[.]", ".", StringComparison.OrdinalIgnoreCase)
            .Replace("(.)", ".", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Extracts a normalized domain from a URL.
    /// </summary>
    /// <param name="value">URL value.</param>
    /// <returns>Domain, or null when parsing fails.</returns>
    private static string? ExtractDomain(string value) =>
        Uri.TryCreate(NormalizeUrl(value), UriKind.Absolute, out var uri)
            ? uri.Host.Trim().TrimEnd('.').ToLowerInvariant().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase)
            : null;

    /// <summary>
    /// Hashes sender and URL values before exposing them in simulated API payloads.
    /// </summary>
    /// <param name="value">Value to hash.</param>
    /// <returns>SHA-256 hash.</returns>
    private static string Hash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"sha256:{Convert.ToHexString(bytes).ToLowerInvariant()}";
    }

    /// <summary>
    /// Compiled URL detector used by the simulator.
    /// </summary>
    /// <returns>URL regex.</returns>
    [GeneratedRegex(@"(?:https?|hxxps?)://[^\s""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();
}
