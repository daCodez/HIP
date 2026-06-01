using HIP.Application.SecondLife;

namespace HIP.Tests.SecondLife;

/// <summary>
/// Verifies the Second Life HUD simulator behavior without requiring Second Life runtime testing.
/// </summary>
[TestFixture]
public sealed class SecondLifeHudSimulationTests
{
    /// <summary>
    /// Confirms harmless chat does not create alerts or send private text to HIP.
    /// </summary>
    [Test]
    public void Safe_message_returns_no_action()
    {
        var result = Service().Simulate(Request(message: "Hello, are you coming to the meeting?"));

        Assert.Multiple(() =>
        {
            Assert.That(result.RiskLevel, Is.EqualTo("Safe"));
            Assert.That(result.RecommendedHudAction, Is.EqualTo(SecondLifeHudRecommendedAction.NoAction));
            Assert.That(result.PrivacySafePayload["sentToHip"], Is.EqualTo("false"));
        });
    }

    /// <summary>
    /// Confirms shortened URLs are detected and included as privacy-safe URL facts.
    /// </summary>
    [Test]
    public void Shortened_url_triggers_scan()
    {
        var result = Service().Simulate(Request(message: "check this https://bit.ly/prize"));

        Assert.That(result.Reasons, Does.Contain("Shortened URL detected."));
        Assert.That(result.PrivacySafePayload["domain"], Is.EqualTo("bit.ly"));
    }

    /// <summary>
    /// Confirms broken-up URLs are reconstructed enough for safety-page routing.
    /// </summary>
    [Test]
    public void Broken_up_url_triggers_scan()
    {
        var result = Service().Simulate(Request(message: "claim at https://badsite dot com now"));

        Assert.That(result.Reasons, Does.Contain("Broken-up URL detected."));
        Assert.That(result.SafetyPageWouldBeUsed, Is.True);
    }

    /// <summary>
    /// Confirms hxxp-style obfuscation triggers a high-risk simulation result.
    /// </summary>
    [Test]
    public void Obfuscated_hxxp_url_triggers_scan()
    {
        var result = Service().Simulate(Request(message: "visit hxxps://bad.example/path"));

        Assert.That(result.Reasons, Does.Contain("Obfuscated hxxp URL detected."));
        Assert.That(result.RiskLevel, Is.EqualTo("High"));
    }

    /// <summary>
    /// Confirms reward-bait wording contributes to risk.
    /// </summary>
    [Test]
    public void Reward_bait_wording_increases_risk()
    {
        var result = Service().Simulate(Request(message: "claim your prize https://example.com"));

        Assert.That(result.Reasons, Does.Contain("Reward bait wording detected."));
        Assert.That(result.Score, Is.LessThan(90));
    }

    /// <summary>
    /// Confirms medium risk creates a private warning in Normal mode.
    /// </summary>
    [Test]
    public void Medium_risk_creates_private_warning_in_normal_mode()
    {
        var result = Service().Simulate(Request(message: "open https://tinyurl.com/test"));

        Assert.That(result.RiskLevel, Is.EqualTo("Medium"));
        Assert.That(result.OwnerWarningWouldShow, Is.True);
    }

    /// <summary>
    /// Confirms high risk uses a popup only when popup alerts are enabled.
    /// </summary>
    [Test]
    public void High_risk_creates_popup_only_when_enabled()
    {
        var enabled = Service().Simulate(Request(message: "claim prize at hxxps://badsite dot com", popupAlertsEnabled: true));
        var disabled = Service().Simulate(Request(message: "claim prize at hxxps://badsite dot com", popupAlertsEnabled: false));

        Assert.Multiple(() =>
        {
            Assert.That(enabled.PopupWouldShow, Is.True);
            Assert.That(disabled.PopupWouldShow, Is.False);
        });
    }

    /// <summary>
    /// Confirms critical risk uses the strongest HUD action and safety-page routing.
    /// </summary>
    [Test]
    public void Critical_risk_uses_safety_page_block_warning()
    {
        var result = Service().Simulate(Request(message: "critical malware at https://free-gift.ru/pay"));

        Assert.Multiple(() =>
        {
            Assert.That(result.RiskLevel, Is.EqualTo("Critical"));
            Assert.That(result.RecommendedHudAction, Is.EqualTo(SecondLifeHudRecommendedAction.CriticalBlockWarning));
            Assert.That(result.SafetyPageWouldBeUsed, Is.True);
        });
    }

    /// <summary>
    /// Confirms Quiet mode suppresses lower-risk owner interruptions.
    /// </summary>
    [Test]
    public void Quiet_mode_suppresses_low_and_medium_alerts()
    {
        var result = Service().Simulate(Request(message: "open https://bit.ly/test", scanMode: "Quiet"));

        Assert.That(result.RecommendedHudAction, Is.EqualTo(SecondLifeHudRecommendedAction.HudStatusOnly));
        Assert.That(result.OwnerWarningWouldShow, Is.False);
    }

    /// <summary>
    /// Confirms the simulated payload excludes full private text and full chat log fields.
    /// </summary>
    [Test]
    public void Privacy_safe_payload_excludes_full_private_text()
    {
        var result = Service().Simulate(Request(
            sourceType: SecondLifeHudSimulationSourceType.PrivateIM,
            message: "claim your prize at hxxps://badsite dot com"));

        Assert.Multiple(() =>
        {
            Assert.That(result.RawPrivateTextExcluded, Is.True);
            Assert.That(result.PrivacySafePayload.Keys, Does.Not.Contain("messageText"));
            Assert.That(result.PrivacySafePayload.Keys, Does.Not.Contain("privateChatLog"));
            Assert.That(result.PrivacySafePayload.Keys, Does.Not.Contain("limitedSuspiciousSnippet"));
        });
    }

    /// <summary>
    /// Confirms invalid scan modes are rejected so settings cannot silently drift.
    /// </summary>
    [Test]
    public void Invalid_scan_mode_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => Service().Simulate(Request(scanMode: "Aggressive")));
    }

    /// <summary>
    /// Confirms invalid source enum values are rejected.
    /// </summary>
    [Test]
    public void Invalid_source_type_is_rejected()
    {
        var request = Request(sourceType: (SecondLifeHudSimulationSourceType)999);

        Assert.Throws<ArgumentException>(() => Service().Simulate(request));
    }

    /// <summary>
    /// Creates a simulator service instance.
    /// </summary>
    /// <returns>The simulator service.</returns>
    private static SecondLifeHudSimulationService Service() => new();

    /// <summary>
    /// Creates a simulator request with secure defaults for individual tests.
    /// </summary>
    /// <param name="sender">Sender label.</param>
    /// <param name="sourceType">Source type.</param>
    /// <param name="message">Message text.</param>
    /// <param name="scanMode">Scan mode.</param>
    /// <param name="popupAlertsEnabled">Whether popups are enabled.</param>
    /// <returns>A simulator request.</returns>
    private static SecondLifeHudSimulationRequest Request(
        string sender = "Example Resident",
        SecondLifeHudSimulationSourceType sourceType = SecondLifeHudSimulationSourceType.GroupChat,
        string message = "hello",
        string scanMode = "Normal",
        bool popupAlertsEnabled = true) =>
        new(
            sender,
            message,
            sourceType,
            null,
            scanMode,
            popupAlertsEnabled,
            true,
            true);
}
