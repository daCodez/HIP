using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies the SL HUD simulation API contract.
/// </summary>
[TestFixture]
public sealed class SecondLifeHudSimulationApiTests
{
    /// <summary>
    /// Confirms the simulation endpoint returns a high-risk result and payload preview.
    /// </summary>
    [Test]
    public async Task Sl_hud_simulation_route_returns_payload_preview()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/simulate", new
        {
            sender = "Example Resident",
            sourceType = "GroupChat",
            messageText = "claim your prize at hxxps://badsite dot com",
            detectedUrls = Array.Empty<string>(),
            scanMode = "Normal",
            popupAlertsEnabled = true,
            privateWarningsEnabled = true,
            safetyPageRoutingEnabled = true
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var payload = await response.Content.ReadAsStringAsync();
        Assert.That(payload, Does.Contain("privacySafePayload"));
        Assert.That(payload, Does.Contain("SafetyPageWarning").Or.Contain("CriticalBlockWarning"));
    }

    /// <summary>
    /// Confirms invalid scan modes return a bad request.
    /// </summary>
    [Test]
    public async Task Sl_hud_simulation_route_rejects_invalid_scan_mode()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/simulate", new
        {
            sender = "Example Resident",
            sourceType = "GroupChat",
            messageText = "hello",
            detectedUrls = Array.Empty<string>(),
            scanMode = "Aggressive",
            popupAlertsEnabled = true,
            privateWarningsEnabled = true,
            safetyPageRoutingEnabled = true
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
}
