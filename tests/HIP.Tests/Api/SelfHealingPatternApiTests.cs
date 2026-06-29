using System.Net;
using System.Net.Http.Json;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class SelfHealingPatternApiTests
{
    [Test]
    public async Task Self_healing_pattern_routes_require_admin_authorization()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/self-healing/detect-patterns", Findings());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Self_healing_detect_patterns_v1_route_returns_suggestions()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/self-healing/detect-patterns", Findings());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(body, Does.Contain("RepeatedShortenerAbuse").Or.Contain("patternType"));
            Assert.That(body, Does.Contain("suggestedRuleJson"));
            Assert.That(body, Does.Contain("simulationRequired"));
            Assert.That(body, Does.Not.Contain("private chat log"));
        });
    }

    private static HttpClient AdminClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "self-healing-pattern-test");
        return client;
    }

    private static IReadOnlyCollection<SuspiciousFinding> Findings() =>
    [
        Finding("api-pattern-1"),
        Finding("api-pattern-2"),
        Finding("api-pattern-3")
    ];

    private static SuspiciousFinding Finding(string id) =>
        new(
            id,
            FindingType.ShortenedUrlAbuse,
            "shortener-abuse.example",
            $"sha256:{id}",
            "browser-extension",
            RiskStatus.HighRisk,
            "Shortened link abuse detected from privacy-safe URL metadata.",
            DateTimeOffset.UtcNow,
            FindingSourceType.BrowserExtension,
            ReporterTrustLevel.High,
            new Dictionary<string, string>
            {
                ["evidenceType"] = "shortener-domain-signal",
                ["containsPrivateContent"] = "false"
            });
}
