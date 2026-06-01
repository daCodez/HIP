using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Browser;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

/// <summary>
/// Tests the browser scan result API contract used by the Chromium extension.
/// </summary>
[TestFixture]
public sealed class BrowserScanResultApiTests
{
    /// <summary>
    /// Verifies the v1 browser endpoint accepts and stores a privacy-safe scan result.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_saves_result()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("saved").GetBoolean(), Is.True);
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("lastCheckedUtc").GetDateTimeOffset(), Is.Not.EqualTo(default(DateTimeOffset)));
        });
    }

    /// <summary>
    /// Verifies the latest scan result can be retrieved by normalized domain.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_returns_latest_result_by_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());
        var response = await client.GetAsync("/api/v1/browser/scan-results/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.EqualTo(84));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("Trusted"));
            Assert.That(json.RootElement.GetProperty("reasons").GetArrayLength(), Is.GreaterThan(0));
            Assert.That(json.RootElement.GetProperty("linksScanned").GetInt32(), Is.EqualTo(42));
        });
    }

    /// <summary>
    /// Verifies the retrieve response avoids private URL, page text, and form content fields.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_does_not_expose_private_fields()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest());
        var response = await client.GetAsync("/api/v1/browser/scan-results/example.com");
        var json = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Not.Contain("pageUrl"));
            Assert.That(json, Does.Not.Contain("pageUrlHash"));
            Assert.That(json, Does.Not.Contain("pageText"));
            Assert.That(json, Does.Not.Contain("formContents"));
            Assert.That(json, Does.Not.Contain("token=secret"));
        });
    }

    /// <summary>
    /// Verifies invalid domains are rejected by the scan result API.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_rejects_invalid_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Domain = "bad domain" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Verifies invalid scores are rejected by the scan result API.
    /// </summary>
    [Test]
    public async Task Scan_result_endpoint_rejects_invalid_score()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/browser/scan-results", ValidRequest() with { Score = -1 });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    /// <summary>
    /// Creates a valid browser scan result request for API tests.
    /// </summary>
    /// <returns>A valid privacy-safe scan result request.</returns>
    private static BrowserScanResultSaveRequest ValidRequest() =>
        new(
            "example.com",
            "https://example.com/page?token=secret",
            84,
            "Trusted",
            "Trusted",
            ["No risky links found"],
            42,
            2,
            2,
            0,
            "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal",
                ["apiStatus"] = "Available"
            });
}
