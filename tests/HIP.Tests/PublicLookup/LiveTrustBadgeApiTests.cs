using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.PublicLookup;

public sealed class LiveTrustBadgeApiTests
{
    [Test]
    public async Task Badge_endpoint_returns_score_status_and_domain()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("domain").GetString(), Is.EqualTo("example.com"));
        Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.InRange(0, 100));
        Assert.That(json.RootElement.GetProperty("status").GetString(), Is.Not.Empty);
    }

    [Test]
    public async Task Badge_always_includes_score_or_status_and_lookup_link()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/verified-example.com");

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.TryGetProperty("score", out _), Is.True, "Legacy score remains for compatibility.");
        Assert.That(json.RootElement.TryGetProperty("status", out _), Is.True);
        Assert.That(json.RootElement.GetProperty("displayScore").ValueKind, Is.EqualTo(JsonValueKind.Null));
        Assert.That(json.RootElement.GetProperty("scorePresentation").GetString(), Is.EqualTo("WithheldInsufficientEvidence"));
        Assert.That(json.RootElement.GetProperty("evidenceCoverage").GetString(), Is.EqualTo("Insufficient"));
        Assert.That(json.RootElement.GetProperty("lookupUrl").GetString(), Is.EqualTo("/lookup/verified-example.com"));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Contain("Not enough evidence yet"));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Not.Contain("/100"));
    }

    [Test]
    public async Task Badge_rejects_invalid_domain()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/bad%20domain");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Badge_does_not_expose_private_data()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/example.com");
        var json = await response.Content.ReadAsStringAsync();

        Assert.That(json, Does.Not.Contain("privateChat"));
        Assert.That(json, Does.Not.Contain("rawEvidence"));
        Assert.That(json, Does.Not.Contain("reporterIdentity"));
        Assert.That(json, Does.Not.Contain("browsingHistory"));
    }

    [Test]
    public async Task Low_score_badge_still_shows_low_score()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/danger-example.com");

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.LessThanOrEqualTo(40));
        Assert.That(json.RootElement.GetProperty("displayScore").GetInt32(), Is.EqualTo(json.RootElement.GetProperty("score").GetInt32()));
        Assert.That(json.RootElement.GetProperty("scorePresentation").GetString(), Is.EqualTo("Available"));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Contain(json.RootElement.GetProperty("displayScore").GetInt32().ToString()));
    }

    [Test]
    public async Task Badge_script_returns_renderable_content()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/example.com/script");
        var script = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/javascript"));
        Assert.That(script, Does.Contain("renderHipLiveTrustBadge"));
        Assert.That(script, Does.Contain("HIP Identity Verified"));
        Assert.That(script, Does.Contain("Not enough evidence yet"));
        Assert.That(script, Does.Contain("displayScore"));
        Assert.That(script, Does.Not.Contain("badge.score)}/100"));
        Assert.That(script, Does.Contain("/api/v1/badge/"));
        Assert.That(script, Does.Contain("position: fixed"));
        Assert.That(script, Does.Contain("background: transparent"));
        Assert.That(script, Does.Contain("shieldMarkup"));
        Assert.That(script, Does.Contain("/hip-logo.svg"));
        Assert.That(script, Does.Contain("data-hip-action=\"minimize\""));
        Assert.That(script, Does.Contain("data-hip-action=\"close\""));
        Assert.That(script, Does.Contain("data-hip-action=\"show\""));
        Assert.That(script, Does.Contain("prefers-reduced-motion"));
        Assert.That(script, Does.Not.Contain("localStorage"));
        Assert.That(script, Does.Not.Contain("sessionStorage"));
    }
}
