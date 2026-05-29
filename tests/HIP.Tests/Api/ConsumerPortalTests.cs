using System.Net;
using System.Net.Http.Json;
using HIP.Application.Consumer;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class ConsumerPortalTests
{
    [Test]
    public async Task Consumer_status_returns_protection_status()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var status = await client.GetFromJsonAsync<ConsumerStatus>("/api/v1/consumer/status");

        Assert.That(status!.ProtectionStatus, Is.EqualTo("Active"));
        Assert.That(status.Message, Does.Contain("Second Life HUD"));
    }

    [Test]
    public async Task Scan_history_does_not_expose_private_content()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var secretPath = "private-secret-path";
        var senderHash = "sender-hash-private";

        await client.PostAsJsonAsync("/api/v1/public/risk-findings", Report(secretPath, senderHash));
        AddConsumer(client);

        var body = await client.GetStringAsync("/api/v1/consumer/scans");

        Assert.That(body, Does.Contain("risky.example"));
        Assert.That(body, Does.Contain("Suspicious link summary."));
        Assert.That(body, Does.Not.Contain(secretPath));
        Assert.That(body, Does.Not.Contain(senderHash));
    }

    [Test]
    public async Task Report_history_returns_report_statuses()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/v1/public/risk-findings", Report("path", "sender-hash"));
        AddConsumer(client);

        var reports = await client.GetFromJsonAsync<IReadOnlyCollection<ConsumerReportHistoryItem>>("/api/v1/consumer/reports");

        Assert.That(reports, Is.Not.Empty);
        Assert.That(reports!.First().Status, Is.EqualTo(ConsumerReportStatus.Submitted));
    }

    [Test]
    public async Task Settings_can_be_loaded()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var settings = await client.GetFromJsonAsync<ConsumerSettings>("/api/v1/consumer/settings");

        Assert.That(settings!.ScanMode, Is.EqualTo("Normal"));
        Assert.That(settings.EnableSafetyPageRouting, Is.True);
    }

    [Test]
    public async Task Settings_can_be_saved()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/consumer/settings", new ConsumerSettings(
            EnablePopupAlerts: false,
            EnablePrivateWarnings: true,
            EnableSafetyPageRouting: true,
            ScanMode: "Strict"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var settings = await client.GetFromJsonAsync<ConsumerSettings>("/api/v1/consumer/settings");
        Assert.That(settings!.ScanMode, Is.EqualTo("Strict"));
        Assert.That(settings.EnablePopupAlerts, Is.False);
    }

    [Test]
    public async Task Invalid_scan_mode_is_rejected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/consumer/settings", new ConsumerSettings(
            EnablePopupAlerts: true,
            EnablePrivateWarnings: true,
            EnableSafetyPageRouting: true,
            ScanMode: "Extreme"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Consumer_apis_are_protected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/consumer/status");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Consumer_route_exists_for_authenticated_consumer()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.GetAsync("/consumer");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    private static HttpClient ConsumerClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        AddConsumer(client);
        return client;
    }

    private static void AddConsumer(HttpClient client)
    {
        client.DefaultRequestHeaders.Remove("X-HIP-Consumer-Id");
        client.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", "consumer-test-device");
    }

    private static RiskFindingReport Report(string path, string senderHash) =>
        new(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "risky.example",
            "hash-1",
            $"https://risky.example/{path}",
            senderHash,
            RiskStatus.HighRisk,
            "Suspicious link summary.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Privacy-safe evidence summary.", new Dictionary<string, string>()),
            "hip-signature-placeholder");
}
