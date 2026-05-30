using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Identity;
using HIP.Application.Reporting;
using HIP.Application.Simulation;
using HIP.Domain.Identity;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.Rules;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using FindingReporterTrustLevel = HIP.Domain.SelfHealing.ReporterTrustLevel;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class ApiVersioningTests
{
    [Test]
    public async Task Public_lookup_v1_route_works()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/lookup/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        Assert.That(json.RootElement.TryGetProperty("finalHipScore", out _), Is.True);
        Assert.That(json.RootElement.TryGetProperty("status", out _), Is.True);
    }

    [Test]
    public async Task Badge_v1_route_works()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/badge/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.TryGetProperty("score", out _), Is.True);
        Assert.That(json.RootElement.TryGetProperty("status", out _), Is.True);
    }

    [Test]
    public async Task Risk_finding_v1_route_works()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/public/risk-findings", RiskFinding());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var result = await response.Content.ReadFromJsonAsync<RiskFindingIngestionResponse>();
        Assert.That(result!.Accepted, Is.True);
        Assert.That(result.NormalizedDomain, Is.EqualTo("risky.example"));
    }

    [Test]
    public async Task Admin_simulation_v1_route_works()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");

        var response = await client.PostAsJsonAsync("/api/v1/admin/rules/simulate", new
        {
            Rule = Rule(),
            TestCases = Array.Empty<RuleSimulationTestCase>()
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Identity_v1_route_works()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/identity/register", new IdentityRegistrationRequest(
            IdentitySubjectType.Domain,
            "example.com",
            "example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Old_unversioned_routes_are_removed()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        Assert.That((await client.GetAsync("/api/public/lookup/domain/example.com")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        Assert.That((await client.GetAsync("/api/admin/audit-logs")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        Assert.That((await client.PostAsJsonAsync("/api/identity/register", new IdentityRegistrationRequest(
            IdentitySubjectType.Domain,
            "example.com",
            "example.com"))).StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public void Browser_extension_config_points_to_v1_routes()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "clients/browser-extension/src/hipApiClient.js"));

        Assert.That(source, Does.Contain("/api/v1/public/lookup/domain/"));
        Assert.That(source, Does.Contain("/api/v1/public/risk-findings"));
        Assert.That(source, Does.Contain("/api/v1/browser/score-site"));
        Assert.That(source, Does.Contain("/api/v1/browser/scan-links"));
        Assert.That(source, Does.Not.Contain("/api/public/lookup"));
    }

    [Test]
    public void Badge_script_points_to_v1_routes()
    {
        var source = File.ReadAllText(Path.Combine(RepositoryRoot(), "src/HIP.Web/wwwroot/hip-badge.js"));

        Assert.That(source, Does.Contain("/api/v1/public/badge/domain/"));
        Assert.That(source, Does.Not.Contain("/api/public/badge"));
    }

    private static RiskFindingReport RiskFinding() =>
        new(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "risky.example",
            "hash-1",
            null,
            null,
            RiskStatus.HighRisk,
            "Test finding for versioned route.",
            DateTimeOffset.UtcNow,
            FindingReporterTrustLevel.Trusted,
            new PrivacySafeEvidence("test", "No private content.", new Dictionary<string, string>()),
            "hip-signature-placeholder");

    private static TrustRule Rule() =>
        new(
            "api-versioning-test-rule",
            "API versioning test rule",
            "Test rule for v1 simulation route.",
            true,
            RuleMode.Watch,
            RuleSeverity.Caution,
            [new RuleCondition("url.hasKnownRisk", RuleOperator.Equals, JsonSerializer.SerializeToElement(true))],
            [new RuleAction(RuleActionType.AddReason, JsonSerializer.SerializeToElement("Known risk signal."))],
            false,
            true,
            "test",
            "API versioning test",
            ApprovalStatus.NotRequired,
            0,
            1);

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate HIP repository root.");
    }
}
