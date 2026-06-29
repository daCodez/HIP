using System.Net;
using System.Net.Http.Json;
using HIP.Domain.Reporting;
using HIP.Domain.Risk;
using HIP.Tests.Reporting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class PrivacySafeReportsApiTests
{
    [Test]
    public async Task Reports_api_accepts_privacy_safe_report()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/reports", PrivacySafeReportingTests.Report());
        var result = await response.Content.ReadFromJsonAsync<PrivacySafeReportResponse>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(result!.Accepted, Is.True);
        Assert.That(result.UrlHash, Does.StartWith("sha256:"));
    }

    [Test]
    public async Task Reports_api_rejects_invalid_report_type()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/reports", PrivacySafeReportingTests.Report() with { ReportType = (ReportType)999 });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Consumer_report_list_only_shows_safe_fields()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/v1/public/risk-findings", RiskFinding("private-path", "sender-private"));
        client.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", "consumer-report-safe");

        var body = await client.GetStringAsync("/api/v1/consumer/reports");

        Assert.That(body, Does.Contain("risk.example"));
        Assert.That(body, Does.Not.Contain("private-path"));
        Assert.That(body, Does.Not.Contain("sender-private"));
    }

    [Test]
    public async Task Admin_report_list_does_not_expose_private_content_by_default()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/v1/reports", PrivacySafeReportingTests.Report() with
        {
            RiskyUrl = "https://risk.example/private-path"
        });
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Moderator");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "report-admin");

        var body = await client.GetStringAsync("/api/v1/admin/reports");

        Assert.That(body, Does.Contain("risk.example"));
        Assert.That(body, Does.Contain("sha256:"));
        Assert.That(body, Does.Not.Contain("private-path"));
        Assert.That(body, Does.Not.Contain("\"riskyUrl\""));
    }

    [Test]
    public async Task Admin_reports_route_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/reports");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static RiskFindingReport RiskFinding(string path, string senderHash) =>
        new(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            HIP.Domain.Review.TargetType.Url,
            "risk.example",
            "hash-1",
            $"https://risk.example/{path}",
            senderHash,
            RiskStatus.HighRisk,
            "Suspicious link summary.",
            DateTimeOffset.UtcNow,
            HIP.Domain.SelfHealing.ReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Privacy-safe evidence summary.", new Dictionary<string, string>()),
            "hip-signature-placeholder");
}
