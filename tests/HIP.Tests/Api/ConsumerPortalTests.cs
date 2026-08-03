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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var status = await client.GetFromJsonAsync<ConsumerStatus>("/api/v1/consumer/status");

        Assert.Multiple(() =>
        {
            Assert.That(status!.ProtectionStatus, Is.EqualTo("Active"));
            Assert.That(status.DeviceStatus, Is.EqualTo("No registered devices"));
            Assert.That(status.Message, Does.Contain("owned by this consumer account"));
        });
    }

    [Test]
    public async Task Scan_history_does_not_expose_private_content()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var secretPath = "private-secret-path";
        var senderHash = "sender-hash-private";

        AddConsumer(client);
        await client.PostAsJsonAsync("/api/v1/public/risk-findings", Report(secretPath, senderHash));

        var body = await client.GetStringAsync("/api/v1/consumer/scans");

        Assert.That(body, Does.Contain("risky.example"));
        Assert.That(body, Does.Contain("Suspicious link summary."));
        Assert.That(body, Does.Not.Contain(secretPath));
        Assert.That(body, Does.Not.Contain(senderHash));
    }

    [Test]
    public async Task Report_history_returns_report_statuses()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        AddConsumer(client);
        await client.PostAsJsonAsync("/api/v1/public/risk-findings", Report("path", "sender-hash"));

        var reports = await client.GetFromJsonAsync<IReadOnlyCollection<ConsumerReportHistoryItem>>("/api/v1/consumer/reports");

        Assert.That(reports, Is.Not.Empty);
        Assert.That(reports!.First().Status, Is.EqualTo(ConsumerReportStatus.Submitted));
    }

    [Test]
    public async Task Settings_can_be_loaded()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var settings = await client.GetFromJsonAsync<ConsumerSettings>("/api/v1/consumer/settings");

        Assert.That(settings!.ScanMode, Is.EqualTo("Normal"));
        Assert.That(settings.EnableSafetyPageRouting, Is.True);
    }

    [Test]
    public async Task Settings_can_be_saved()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
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
    public async Task Settings_are_isolated_between_authenticated_consumers()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var owner = factory.CreateClient();
        owner.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", "consumer-owner-A");
        using var other = factory.CreateClient();
        other.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", "consumer-owner-B");

        var save = await owner.PostAsJsonAsync("/api/v1/consumer/settings", new ConsumerSettings(
            EnablePopupAlerts: false,
            EnablePrivateWarnings: false,
            EnableSafetyPageRouting: true,
            ScanMode: "Paranoid"));
        var ownerSettings = await owner.GetFromJsonAsync<ConsumerSettings>("/api/v1/consumer/settings");
        var otherSettings = await other.GetFromJsonAsync<ConsumerSettings>("/api/v1/consumer/settings");

        Assert.Multiple(() =>
        {
            Assert.That(save.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(ownerSettings!.ScanMode, Is.EqualTo("Paranoid"));
            Assert.That(otherSettings!.ScanMode, Is.EqualTo("Normal"));
            Assert.That(otherSettings.EnablePopupAlerts, Is.True);
        });
    }

    [Test]
    public async Task Invalid_scan_mode_is_rejected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/consumer/settings", new ConsumerSettings(
            EnablePopupAlerts: true,
            EnablePrivateWarnings: true,
            EnableSafetyPageRouting: true,
            ScanMode: "Extreme"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Invalid_badge_configuration_is_rejected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/consumer/settings", new ConsumerSettings(
            EnablePopupAlerts: true,
            EnablePrivateWarnings: true,
            EnableSafetyPageRouting: true,
            ScanMode: "Normal",
            BadgeConfigurations: new Dictionary<string, ConsumerBadgeConfiguration>(StringComparer.Ordinal)
            {
                ["example.com"] = new("dark", "bottom-right", 12)
            }));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Consumer_apis_are_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/consumer/status");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Consumer_route_exists_for_authenticated_consumer()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.GetAsync("/consumer");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase("/consumer")]
    [TestCase("/consumer/scans")]
    [TestCase("/consumer/reports")]
    [TestCase("/consumer/appeals")]
    [TestCase("/consumer/alerts")]
    [TestCase("/consumer/devices")]
    [TestCase("/consumer/licenses")]
    [TestCase("/consumer/security")]
    public async Task Completed_consumer_routes_require_and_accept_the_consumer_policy(string route)
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var consumer = ConsumerClient(factory);

        var denied = await anonymous.GetAsync(route);
        var allowed = await consumer.GetAsync(route);

        Assert.Multiple(() =>
        {
            Assert.That(denied.StatusCode, Is.EqualTo(HttpStatusCode.Found), route);
            Assert.That(
                denied.Headers.Location?.OriginalString,
                Is.EqualTo($"/login?returnUrl={Uri.EscapeDataString(route)}"),
                route);
            Assert.That(allowed.StatusCode, Is.EqualTo(HttpStatusCode.OK), route);
        });
    }

    [Test]
    public async Task Consumer_home_uses_live_owner_status_and_has_no_future_placeholder_cards()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var html = await client.GetStringAsync("/consumer");

        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Contain("No registered devices"));
            Assert.That(html, Does.Contain("Not linked"));
            Assert.That(html, Does.Contain("href=\"/licenses\""));
            Assert.That(html, Does.Contain("href=\"/security\""));
            Assert.That(html, Does.Not.Contain("<strong>Dev</strong>"));
            Assert.That(html, Does.Not.Contain("<strong>Later</strong>"));
        });
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
