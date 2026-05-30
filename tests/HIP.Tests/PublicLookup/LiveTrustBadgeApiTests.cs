using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.PublicLookup;

public sealed class LiveTrustBadgeApiTests
{
    [Test]
    public async Task Badge_endpoint_returns_score_status_and_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/verified-example.com");

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.TryGetProperty("score", out _), Is.True);
        Assert.That(json.RootElement.TryGetProperty("status", out _), Is.True);
        Assert.That(json.RootElement.GetProperty("lookupUrl").GetString(), Is.EqualTo("/lookup/verified-example.com"));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Contain("Score:"));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Contain("Status:"));
    }

    [Test]
    public async Task Badge_rejects_invalid_domain()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/bad%20domain");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Badge_does_not_expose_private_data()
    {
        await using var factory = new WebApplicationFactory<Program>();
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
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/danger-example.com");

        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("score").GetInt32(), Is.LessThanOrEqualTo(40));
        Assert.That(json.RootElement.GetProperty("badgeText").GetString(), Does.Contain(json.RootElement.GetProperty("score").GetInt32().ToString()));
    }

    [Test]
    public async Task Badge_script_returns_renderable_content()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/badge/example.com/script");
        var script = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/javascript"));
        Assert.That(script, Does.Contain("renderHipLiveTrustBadge"));
        Assert.That(script, Does.Contain("Score:"));
        Assert.That(script, Does.Contain("Status:"));
        Assert.That(script, Does.Contain("/api/v1/badge/"));
    }
}
