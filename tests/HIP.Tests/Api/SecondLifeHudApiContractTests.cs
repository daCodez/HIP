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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Support");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "support-sl-hud-test");

        var setupCodeResponse = await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "support-sl-hud-test",
            initialScanMode = "Normal"
        });
        Assert.That(setupCodeResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var setupCodeJson = await JsonDocument.ParseAsync(await setupCodeResponse.Content.ReadAsStreamAsync());
        var setupCode = setupCodeJson.RootElement.GetProperty("setupCode").GetString();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode,
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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateHudAsync(client);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", new
        {
            deviceId = activation.DeviceId,
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
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateHudAsync(client);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);

        var response = await client.PostAsJsonAsync($"/api/v1/sl-hud/settings/{activation.DeviceId}", new
        {
            deviceId = activation.DeviceId,
            mode = "Aggressive",
            popupAlertsEnabled = true,
            privateWarningsEnabled = true,
            safetyRoutingEnabled = true
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    private static async Task<HudActivation> ActivateHudAsync(HttpClient client)
    {
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-HIP-Admin-Role", "Support");
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-HIP-Admin-User", "hud-contract-test");
        var setupCodeResponse = await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "hud-contract-test",
            initialScanMode = "Normal"
        });
        setupCodeResponse.EnsureSuccessStatusCode();
        using var setupCodeJson = await JsonDocument.ParseAsync(await setupCodeResponse.Content.ReadAsStreamAsync());

        var activationResponse = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode = setupCodeJson.RootElement.GetProperty("setupCode").GetString(),
            avatarIdHash = $"avatar-{Guid.NewGuid():N}",
            hudVersion = "contract-test"
        });
        activationResponse.EnsureSuccessStatusCode();
        using var activationJson = await JsonDocument.ParseAsync(await activationResponse.Content.ReadAsStreamAsync());

        return new HudActivation(
            activationJson.RootElement.GetProperty("deviceId").GetString()!,
            activationJson.RootElement.GetProperty("deviceCredential").GetString()!);
    }

    private sealed record HudActivation(string DeviceId, string DeviceCredential);
}
