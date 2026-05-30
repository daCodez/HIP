using HIP.Application.Reporting;
using HIP.Domain.Reporting;
using HIP.Domain.Risk;

namespace HIP.Tests.Reporting;

public sealed class PrivacySafeReportingTests
{
    [Test]
    public async Task Report_can_be_submitted()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report(), CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(response.ReportId, Is.Not.Empty);
    }

    [Test]
    public async Task Report_rejects_invalid_report_type()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { ReportType = (ReportType)999 }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
        Assert.That(response.Message, Does.Contain("Report Type"));
    }

    [Test]
    public async Task Report_rejects_oversized_content()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { ReasonSummary = new string('x', PrivacySafeReportValidator.MaxReasonLength + 1) }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
    }

    [Test]
    public async Task Report_stores_url_hash()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { UrlHash = null, RiskyUrl = "https://risk.example/path?secret=not-stored" }, CancellationToken.None);
        var stored = await service.ListAsync(CancellationToken.None);

        Assert.That(response.UrlHash, Does.StartWith("sha256:"));
        Assert.That(stored.Single().UrlHash, Does.StartWith("sha256:"));
    }

    [Test]
    public async Task Report_does_not_store_full_private_chat_logs()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with
        {
            ReasonSummary = "Full private chat log: hello"
        }, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
    }

    [Test]
    public async Task Report_status_defaults_to_submitted()
    {
        var service = Service();

        var response = await service.SubmitAsync(Report() with { Status = ReportStatus.Closed }, CancellationToken.None);
        var stored = await service.ListAsync(CancellationToken.None);

        Assert.That(response.Status, Is.EqualTo(ReportStatus.Submitted));
        Assert.That(stored.Single().Status, Is.EqualTo(ReportStatus.Submitted));
    }

    [Test]
    public void Retention_policy_maps_normal_risky_findings_to_90_days()
    {
        var policy = new ReportRetentionPolicyService().GetPolicy(ReportRetentionCategory.NormalRiskyFinding);

        Assert.That(policy.RetentionPeriod, Is.EqualTo(TimeSpan.FromDays(90)));
    }

    [Test]
    public void Confirmed_dangerous_pattern_can_be_long_term()
    {
        var policy = new ReportRetentionPolicyService().GetPolicy(ReportRetentionCategory.ConfirmedDangerousPattern);

        Assert.That(policy.RetentionPeriod, Is.Null);
        Assert.That(policy.Reason, Does.Contain("long-term"));
    }

    private static PrivacySafeReportService Service() =>
        new(new PrivacySafeReportValidator(), new Sha256PrivacyHashingService());

    public static PrivacySafeReport Report() =>
        new(
            "",
            ReportType.RiskyUrl,
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            "Risk.Example",
            "https://risk.example/path",
            null,
            "sender@example",
            "device-1",
            RiskStatus.HighRisk,
            "Suspicious shortened URL pattern.",
            DateTimeOffset.UtcNow,
            ReportStatus.Submitted,
            new PrivacySafeEvidence("url", "Risky URL domain and URL hash only.", new Dictionary<string, string> { ["targetDomain"] = "risk.example" }),
            "hip-signature-placeholder");
}
