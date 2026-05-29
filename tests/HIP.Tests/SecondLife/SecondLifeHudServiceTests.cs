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
        Assert.That(response.ClientConfig.ReportFindingUrl, Is.EqualTo("/api/v1/public/sl-hud/report-finding"));
    }

    private static SecondLifeHudService Service(IReviewQueueService? reviewQueueService = null)
    {
        var ingestion = new RiskFindingIngestionService(
            new RiskFindingReportValidator(),
            new InMemoryRiskFindingReportRepository(),
            reviewQueueService ?? new ReviewQueueService(new ReviewItemValidator(), new AuditLogService()),
            new PatternDetectionService());

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
