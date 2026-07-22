using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Safety;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class SafetyApiTests
{
    [Test]
    public async Task Safety_page_loads_with_valid_url()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/safety?url=https%3A%2F%2Fbit.ly%2Fexample&source=browser");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await response.Content.ReadAsStringAsync();
        Assert.That(html, Does.Contain("HIP Safety Page"));
    }

    [Test]
    public async Task Safety_evaluate_rejects_invalid_url()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/safety/evaluate", new { Url = "javascript:alert(1)", Source = "browser" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Suspicious_url_routes_to_warning()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/safety/evaluate", new { Url = "https://bit.ly/example", Source = "browser" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("riskLevel").GetString(), Is.EqualTo("Suspicious"));
        Assert.That(json.RootElement.GetProperty("shouldRouteToSafetyPage").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("allowContinue").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("continuationRequirement").GetString(), Is.EqualTo("Confirmation"));
        Assert.That(json.RootElement.GetProperty("pageTrustScore").GetInt32(), Is.InRange(0, 100));
        Assert.That(json.RootElement.GetProperty("contentRiskScore").GetInt32(), Is.InRange(0, 100));
        Assert.That(json.RootElement.GetProperty("contentRiskScoreHigherMeansMoreRisk").GetBoolean(), Is.True);
    }

    [Test]
    public async Task Critical_url_blocks_continue()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/safety/evaluate", new { Url = "https://critical-example.com/pay", Source = "sl-hud" });

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("riskLevel").GetString(), Is.EqualTo("Critical"));
        Assert.That(json.RootElement.GetProperty("allowContinue").GetBoolean(), Is.False);
        Assert.That(json.RootElement.GetProperty("recommendedAction").GetString(), Is.EqualTo("Block"));
    }

    [Test]
    public async Task Safety_evaluation_response_does_not_expose_private_data()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/safety/evaluate", new { Url = "https://bit.ly/example", Source = "browser" });
        var json = await response.Content.ReadAsStringAsync();

        Assert.That(json, Does.Not.Contain("chatLog"));
        Assert.That(json, Does.Not.Contain("formContents"));
        Assert.That(json, Does.Not.Contain("privateMessage"));
        Assert.That(json, Does.Not.Contain("browsingHistory"));
    }

    /// <summary>
    /// Confirms safety API responses strip query strings and fragments from display URLs to avoid leaking tokens.
    /// </summary>
    [Test]
    public async Task Safety_evaluation_strips_query_and_fragment_from_response_url()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/safety/evaluate", new { Url = "https://bit.ly/example?token=secret#private", Source = "browser" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("url").GetString(), Is.EqualTo("https://bit.ly/example"));
        Assert.That(json.RootElement.GetRawText(), Does.Not.Contain("token=secret"));
        Assert.That(json.RootElement.GetRawText(), Does.Not.Contain("#private"));
    }

    [Test]
    public async Task Safety_url_handling_avoids_open_redirect()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var response = await client.GetAsync("/safety?url=https%3A%2F%2Fdanger-example.com%2Fpay&source=browser");

        Assert.That((int)response.StatusCode, Is.LessThan(300));
        Assert.That(response.Headers.Location, Is.Null);
    }

    [Test]
    public async Task Dangerous_page_requires_two_actions_and_never_renders_the_target_as_a_link()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        const string target = "https://danger-example.com/pay?token=private#secret";

        var response = await client.GetAsync($"/safety?url={Uri.EscapeDataString(target)}&source=browser-extension");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(html, Does.Contain("Evaluated destination"));
            Assert.That(html, Does.Contain("Exact-page trust"));
            Assert.That(html, Does.Contain("Content risk"));
            Assert.That(html, Does.Contain("higher means more risk"));
            Assert.That(html, Does.Contain("I understand this destination is dangerous"));
            Assert.That(html, Does.Not.Contain($"href=\"{target}"));
            Assert.That(html, Does.Not.Contain("token=private"));
            Assert.That(html, Does.Not.Contain("#secret"));
        });
    }

    [Test]
    public async Task Safety_decision_api_enforces_confirmation_and_returns_no_raw_target()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        const string target = "https://danger-example.com/pay?token=private-marker#secret";

        var unconfirmed = await client.PostAsJsonAsync(
            "/api/v1/safety/decisions",
            new SafetyDecisionRequest(
                target,
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: false));
        var confirmed = await client.PostAsJsonAsync(
            "/api/v1/safety/decisions",
            new SafetyDecisionRequest(
                target,
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: true));
        var confirmedBody = await confirmed.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(unconfirmed.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
            Assert.That(confirmed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(confirmedBody, Does.Contain("Recorded"));
            Assert.That(confirmedBody, Does.Not.Contain("private-marker"));
            Assert.That(confirmedBody, Does.Not.Contain("danger-example.com"));
        });
    }

    [Test]
    public async Task Critical_decision_api_blocks_continue_even_when_acknowledged()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/v1/safety/decisions",
            new SafetyDecisionRequest(
                "https://critical-example.com/pay",
                "browser-extension",
                SafetyDecisionAction.Continue,
                DangerAcknowledged: true));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [TestCase("report-safe")]
    [TestCase("report-dangerous")]
    public async Task Report_endpoints_persist_privacy_safe_decisions(string route)
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            $"/api/v1/safety/{route}",
            new
            {
                Url = "https://danger-example.com/pay?token=private-marker#secret",
                Source = "browser-extension",
                Reason = "User-selected report action."
            });
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("Privacy-safe report"));
            Assert.That(body, Does.Not.Contain("private-marker"));
            Assert.That(body, Does.Not.Contain("#secret"));
        });
    }
}
