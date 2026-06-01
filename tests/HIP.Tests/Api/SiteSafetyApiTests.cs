using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.SiteSafety;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

/// <summary>
/// API tests for the versioned HIP Site Safety Scan endpoint.
/// </summary>
[TestFixture]
public sealed class SiteSafetyApiTests
{
    /// <summary>
    /// Verifies the v1 API returns public-safe scan data for a valid public URL.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_v1_route_returns_scan_result()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest("https://example.com"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
            Assert.That(json.RootElement.GetProperty("status").GetString(), Is.EqualTo("LimitedData"));
            Assert.That(json.RootElement.TryGetProperty("pageText", out _), Is.False);
            Assert.That(json.RootElement.TryGetProperty("formValues", out _), Is.False);
        });
    }

    /// <summary>
    /// Verifies localhost and internal URLs are rejected to avoid SSRF abuse.
    /// </summary>
    [Test]
    public async Task Site_safety_scan_rejects_localhost_url()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/site-safety/scan", new SiteSafetyScanRequest("http://localhost:5123"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
}
