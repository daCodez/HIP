using System.Net;
using System.Net.Http.Json;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AiRiskAnalysisApiTests
{
    [Test]
    public async Task Ai_analysis_requires_admin_authorization()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/ai/analyze-url", new
        {
            Url = "https://bit.ly/example",
            Domain = "bit.ly",
            RiskReasonSummary = "Shortened link detected.",
            Platform = "Web"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Ai_url_analysis_v1_route_returns_privacy_safe_result()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/ai/analyze-url", new
        {
            Url = "https://bit.ly/win-now",
            Domain = "bit.ly",
            RiskReasonSummary = "Limited time reward claim.",
            Platform = "Web",
            RuleSignals = new Dictionary<string, string> { ["url.usesShortener"] = "true" }
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(body, Does.Contain("RouteToSafetyPage"));
            Assert.That(body, Does.Contain("Development deterministic HIP AI placeholder"));
            Assert.That(body, Does.Not.Contain("pageBody"));
            Assert.That(body, Does.Not.Contain("password"));
        });
    }

    [Test]
    public async Task Ai_content_analysis_rejects_private_content()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/ai/analyze-content", new
        {
            Domain = "example.com",
            Platform = "Chat",
            RiskReasonSummary = "private chat log token=secret"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Ai_suggest_rule_route_returns_rule_that_requires_simulation()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/ai/suggest-rule", new
        {
            Domain = "tinyurl.com",
            Url = "https://tinyurl.com/claim-login",
            Platform = "Web",
            Analysis = new
            {
                RiskLevel = RiskStatus.HighRisk,
                Confidence = 85,
                Reasons = new[] { "Shortened link and credential request pattern." },
                DetectedPatterns = new[] { "ShortenedUrl", "CredentialRequest" },
                RecommendedAction = "RouteToSafetyPage",
                RequiresReview = true,
                SuggestRule = true,
                IsPlaceholder = true,
                ProviderName = "Development deterministic HIP AI placeholder - not production AI"
            }
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var body = await response.Content.ReadAsStringAsync();
        Assert.Multiple(() =>
        {
            Assert.That(body, Does.Contain("simulationRequired"));
            Assert.That(body, Does.Contain("recommendedMode"));
            Assert.That(body, Does.Contain("\"recommendedMode\":1"));
        });
    }

    private static HttpClient AdminClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "ai-risk-test");
        return client;
    }
}
