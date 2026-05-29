using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Dashboard;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminDashboardTests
{
    [Test]
    public async Task Dashboard_summary_returns_counts()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Owner");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var summary = await response.Content.ReadFromJsonAsync<AdminDashboardSummary>();
        Assert.That(summary, Is.Not.Null);
        Assert.That(summary!.Cards.Select(card => card.Key), Does.Contain("totalScans"));
        Assert.That(summary.Cards.Select(card => card.Key), Does.Contain("apiHealth"));
    }

    [Test]
    public async Task Dashboard_summary_does_not_expose_private_content()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var privateToken = "private-token-should-not-appear";
        var senderHash = "sender-hash-should-not-appear";
        var report = new RiskFindingReport(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "risky.example",
            "hash-1",
            $"https://risky.example/{privateToken}",
            senderHash,
            RiskStatus.HighRisk,
            "Suspicious redirect summary.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence(
                "test",
                "Privacy-safe summary only.",
                new Dictionary<string, string> { ["privateEvidence"] = "must-not-render" }),
            "hip-signature-placeholder");

        var ingest = await client.PostAsJsonAsync("/api/v1/public/risk-findings", report);
        Assert.That(ingest.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        AddRole(client, "Owner");
        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(body, Does.Not.Contain(privateToken));
        Assert.That(body, Does.Not.Contain(senderHash));
        Assert.That(body, Does.Not.Contain("must-not-render"));
        Assert.That(body, Does.Contain("Suspicious redirect summary."));
    }

    [Test]
    public async Task Unauthorized_users_cannot_access_admin_dashboard_api()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Readonly_can_view_summary()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Dashboard_route_exists()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.GetAsync("/admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Recent_activity_uses_privacy_safe_summaries()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/v1/public/risk-findings", new RiskFindingReport(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "privacy-safe.example",
            "hash-2",
            "https://privacy-safe.example/secret-path",
            "sender-secret",
            RiskStatus.Dangerous,
            "Known dangerous domain signal.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "Evidence summary.", new Dictionary<string, string>()),
            "hip-signature-placeholder"));

        AddRole(client, "Owner");
        var response = await client.GetAsync("/api/v1/admin/dashboard/summary");
        var summary = await response.Content.ReadFromJsonAsync<AdminDashboardSummary>();

        Assert.That(summary!.RecentActivity, Is.Not.Empty);
        var serialized = JsonSerializer.Serialize(summary.RecentActivity);
        Assert.That(serialized, Does.Contain("Known dangerous domain signal."));
        Assert.That(serialized, Does.Not.Contain("secret-path"));
        Assert.That(serialized, Does.Not.Contain("sender-secret"));
    }

    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-Role");
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-User");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-dashboard-test");
    }
}
