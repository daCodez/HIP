using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class SecondLifeHudApiContractTests
{
    [Test]
    public async Task Sl_hud_activate_route_accepts_valid_setup_code()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode = "HIP-DEV-SETUP",
            avatarIdHash = "avatar-hash",
            hudVersion = "0.1.0"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.That(json.RootElement.GetProperty("activated").GetBoolean(), Is.True);
        Assert.That(json.RootElement.GetProperty("deviceId").GetString(), Does.StartWith("sl-hud-"));
    }

    [Test]
    public async Task Sl_hud_scan_route_returns_warning_action_for_broken_up_url()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", new
        {
            deviceId = "hud-1",
            source = "GroupChat",
            messageText = "limited suspicious snippet",
            detectedUrls = new[] { "hxxps://scam-prize dot example" },
            senderHash = "sender-hash"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Multiple(() =>
        {
            Assert.That(json.RootElement.GetProperty("riskLevel").GetString(), Is.EqualTo("High"));
            Assert.That(json.RootElement.GetProperty("recommendedHudAction").GetString(), Is.EqualTo("PrivateWarningAndPopup"));
            Assert.That(json.RootElement.GetProperty("safetyPageUrl").GetString(), Does.Contain("source=sl-hud"));
        });
    }

    [Test]
    public async Task Sl_hud_settings_route_rejects_invalid_mode()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/settings/hud-1", new
        {
            deviceId = "hud-1",
            mode = "Aggressive",
            popupAlertsEnabled = true,
            privateWarningsEnabled = true,
            safetyRoutingEnabled = true
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }
}
