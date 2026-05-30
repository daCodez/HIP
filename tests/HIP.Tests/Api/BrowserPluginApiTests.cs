using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class BrowserPluginApiTests
{
    [Test]
    public async Task Score_site_endpoint_returns_score_status_and_reasons()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/score-site", new BrowserScoreSiteRequest(
            "https://example.com",
            "example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(0, 100));
        Assert.That(json.RootElement.GetProperty("status").GetString(), Is.Not.Empty);
        Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
    }

    [Test]
    public async Task Scan_links_endpoint_returns_risk_results()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-links", new BrowserScanLinksRequest(
            "https://example.com",
            ["https://example.com/about", "https://bit.ly/example"]));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("results").GetArrayLength(), Is.EqualTo(2));
    }

    [Test]
    public async Task Safe_links_do_not_require_icons()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-links", new BrowserScanLinksRequest(
            "https://example.com",
            ["https://example.com/about"]));

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var result = json.RootElement.GetProperty("results")[0];
        Assert.That(result.GetProperty("requiresIcon").GetBoolean(), Is.False);
        Assert.That(result.GetProperty("recommendedAction").GetString(), Is.EqualTo("Allow"));
    }

    [Test]
    public async Task Suspicious_links_require_labels_or_icons()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-links", new BrowserScanLinksRequest(
            "https://example.com",
            ["https://danger-example.com/pay"]));

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var result = json.RootElement.GetProperty("results")[0];
        Assert.That(result.GetProperty("requiresIcon").GetBoolean(), Is.True);
        Assert.That(result.GetProperty("label").GetString(), Is.Not.Empty);
        Assert.That(result.GetProperty("recommendedAction").GetString(), Is.Not.EqualTo("Allow"));
    }

    [Test]
    public async Task Shortened_links_are_marked_suspicious_or_caution()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-links", new BrowserScanLinksRequest(
            "https://example.com",
            ["https://bit.ly/example"]));

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var result = json.RootElement.GetProperty("results")[0];
        Assert.That(result.GetProperty("requiresIcon").GetBoolean(), Is.True);
        Assert.That(result.GetProperty("label").GetString(), Is.EqualTo("Suspicious"));
        Assert.That(result.GetProperty("reasons")[0].GetString(), Does.Contain("Shortened link"));
    }

    [Test]
    public void Browser_api_request_models_do_not_include_page_text_or_private_content()
    {
        var scoreProperties = typeof(BrowserScoreSiteRequest).GetProperties().Select(property => property.Name).ToArray();
        var scanProperties = typeof(BrowserScanLinksRequest).GetProperties().Select(property => property.Name).ToArray();

        Assert.That(scoreProperties, Is.EquivalentTo(new[] { "Url", "Domain" }));
        Assert.That(scanProperties, Is.EquivalentTo(new[] { "PageUrl", "Links" }));
        Assert.That(scanProperties, Does.Not.Contain("PageText"));
        Assert.That(scanProperties, Does.Not.Contain("PrivateContent"));
        Assert.That(scanProperties, Does.Not.Contain("FormContents"));
    }
}
