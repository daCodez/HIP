using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
}
