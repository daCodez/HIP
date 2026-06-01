using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.SecondLife;
using HIP.Application.SelfHealing;
using HIP.Domain.Risk;

namespace HIP.Tests.SecondLife;

public sealed class SecondLifeHudServiceTests
{
    [Test]
    public void Sl_hud_activation_request_validates_setup_code()
    {
        var service = Service();

        var response = service.Activate(new SecondLifeHudActivationRequest("HIP-DEV-SETUP", "hud-1", "avatar-hash"));

        Assert.That(response.Activated, Is.True);
        Assert.That(response.LicenseStatus, Is.EqualTo("DevelopmentActive"));
    }

    [Test]
    public void Invalid_setup_code_is_rejected()
    {
        var service = Service();

        var response = service.Activate(new SecondLifeHudActivationRequest("bad-code", "hud-1", null));

        Assert.That(response.Activated, Is.False);
        Assert.That(response.LicenseStatus, Is.EqualTo("Inactive"));
    }

    [Test]
    public async Task Hud_report_finding_uses_privacy_safe_dto()
    {
        var service = Service();

        var response = await service.ReportFindingAsync(Report(), CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(response.ReportId, Is.Not.Empty);
    }

    [Test]
    public void Hud_report_does_not_require_full_chat_logs()
    {
        var properties = typeof(SecondLifeHudFindingReport).GetProperties().Select(property => property.Name).ToArray();

        Assert.That(properties, Does.Not.Contain("ChatLog"));
        Assert.That(properties, Does.Not.Contain("PrivateImLog"));
        Assert.That(properties, Does.Not.Contain("MessageBody"));
    }

    [Test]
    public async Task Suspicious_finding_can_create_review_item()
    {
        var review = new ReviewQueueService(new ReviewItemValidator(), new AuditLogService());
        var service = Service(review);

        var response = await service.ReportFindingAsync(Report(RiskStatus.HighRisk), CancellationToken.None);

        Assert.That(response.ReviewCreated, Is.True);
        Assert.That(review.List(), Has.Count.EqualTo(1));
    }

    [Test]
    public async Task Safety_page_route_can_be_returned()
    {
        var service = Service();

        var response = await service.ReportFindingAsync(Report() with { RiskyUrl = "https://risky.example/path" }, CancellationToken.None);

        Assert.That(response.SafetyPageUrl, Does.StartWith("/safety?url="));
        Assert.That(response.SafetyPageUrl, Does.Contain("risky.example"));
    }

    [Test]
    public void License_status_response_is_returned()
    {
        var service = Service();

        var response = service.Activate(new SecondLifeHudActivationRequest("HIP-DEV-SETUP", "hud-1", null));

        Assert.That(response.LicenseStatus, Is.Not.Empty);
        Assert.That(response.ClientConfig.ReportFindingUrl, Is.EqualTo("/api/v1/sl-hud/report"));
        Assert.That(response.DeviceId, Is.EqualTo("hud-1"));
    }

    [Test]
    public void Activation_can_generate_device_id_without_web_login()
    {
        var service = Service();

        var response = service.Activate(new SecondLifeHudActivationRequest("HIP-DEV-SETUP", null, "avatar-hash", "0.1.0"));

        Assert.That(response.Activated, Is.True);
        Assert.That(response.DeviceId, Does.StartWith("sl-hud-"));
        Assert.That(response.HudVersion, Is.EqualTo("0.1.0"));
    }

    [Test]
    public void Hud_scan_detects_suspicious_broken_up_url()
    {
        var service = Service();

        var response = service.Scan(new SecondLifeHudScanRequest(
            "hud-1",
            "GroupChat",
            "limited suspicious snippet only",
            ["hxxps://scam-prize dot example"],
            "sender-hash"));

        Assert.Multiple(() =>
        {
            Assert.That(response.RiskLevel, Is.EqualTo("High"));
            Assert.That(response.Score, Is.EqualTo(32));
            Assert.That(response.Reasons, Does.Contain("Broken-up URL detected"));
            Assert.That(response.RecommendedHudAction, Is.EqualTo("PrivateWarningAndPopup"));
            Assert.That(response.SafetyPageUrl, Does.Contain("source=sl-hud"));
        });
    }

    [Test]
    public void Critical_scan_includes_safety_page_block_flow()
    {
        var service = Service();

        var response = service.Scan(new SecondLifeHudScanRequest(
            "hud-1",
            "PrivateIm",
            "critical malware prize",
            ["https://free-gift.ru/pay"],
            "sender-hash"));

        Assert.Multiple(() =>
        {
            Assert.That(response.RiskLevel, Is.EqualTo("Critical"));
            Assert.That(response.RecommendedHudAction, Is.EqualTo("StrongPopupAndSafetyBlock"));
            Assert.That(response.SafetyPageUrl, Does.StartWith("/safety?url="));
        });
    }

    [Test]
    public void Hud_scan_does_not_require_full_chat_logs()
    {
        var properties = typeof(SecondLifeHudScanRequest).GetProperties().Select(property => property.Name).ToArray();

        Assert.That(properties, Does.Not.Contain("ChatLog"));
        Assert.That(properties, Does.Not.Contain("PrivateImLog"));
        Assert.That(properties, Does.Not.Contain("FullMessageBody"));
    }

    [Test]
    public void Hud_settings_can_enable_and_disable_popup_alerts()
    {
        var service = Service();

        var response = service.SaveSettings("hud-1", new SecondLifeHudSettings("ignored", "Quiet", false, true, true));
        var settings = service.GetSettings("hud-1");

        Assert.Multiple(() =>
        {
            Assert.That(response.Saved, Is.True);
            Assert.That(settings.Mode, Is.EqualTo("Quiet"));
            Assert.That(settings.PopupAlertsEnabled, Is.False);
        });
    }

    [TestCase("Quiet")]
    [TestCase("Normal")]
    [TestCase("Strict")]
    [TestCase("Paranoid")]
    public void Hud_mode_can_be_supported_modes(string mode)
    {
        var service = Service();

        var response = service.SaveSettings("hud-1", new SecondLifeHudSettings("hud-1", mode, true, true, true));

        Assert.That(response.Saved, Is.True);
    }

    [Test]
    public void Invalid_hud_mode_is_rejected()
    {
        var service = Service();

        var response = service.SaveSettings("hud-1", new SecondLifeHudSettings("hud-1", "Aggressive", true, true, true));

        Assert.That(response.Saved, Is.False);
    }

    private static SecondLifeHudService Service(IReviewQueueService? reviewQueueService = null)
    {
        var ingestion = new RiskFindingIngestionService(
            new RiskFindingReportValidator(),
            new InMemoryRiskFindingReportRepository(),
            reviewQueueService ?? new ReviewQueueService(new ReviewItemValidator(), new AuditLogService()),
            new PatternDetectionService(),
            new Sha256PrivacyHashingService());

        return new SecondLifeHudService(ingestion);
    }

    private static SecondLifeHudFindingReport Report(RiskStatus riskStatus = RiskStatus.HighRisk) =>
        new(
            "hud-1",
            "avatar-hash",
            "risky.example",
            "https://risky.example/free-prize",
            null,
            "sender-hash",
            riskStatus,
            "Broken-up URL pattern.",
            DateTimeOffset.UtcNow,
            "sl-hud-signature-placeholder");
}
