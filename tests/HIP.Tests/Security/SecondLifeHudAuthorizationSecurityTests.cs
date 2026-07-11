using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies a public HUD device identifier is never accepted as authorization by itself.
/// </summary>
public sealed class SecondLifeHudAuthorizationSecurityTests
{
    [Test]
    public async Task Hud_scan_requires_the_credential_issued_at_activation()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateAsync(client);
        var request = new
        {
            deviceId = activation.DeviceId,
            source = "GroupChat",
            messageText = "limited suspicious snippet",
            detectedUrls = new[] { "hxxps://risk dot example" },
            senderHash = "privacy-safe-sender-hash"
        };

        var unauthorized = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", request);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);
        var authorized = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", request);

        Assert.Multiple(() =>
        {
            Assert.That(unauthorized.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(authorized.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });
    }

    [Test]
    public async Task Hud_settings_reject_a_credential_for_a_different_device()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateAsync(client);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);

        var response = await client.GetAsync("/api/v1/sl-hud/settings/sl-hud-not-the-activated-device");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static async Task<HudActivation> ActivateAsync(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Support");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "hud-security-test");
        var setupCodeResponse = await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "hud-security-test",
            initialScanMode = "Normal"
        });
        setupCodeResponse.EnsureSuccessStatusCode();
        using var setupCodeJson = await JsonDocument.ParseAsync(await setupCodeResponse.Content.ReadAsStreamAsync());
        var setupCode = setupCodeJson.RootElement.GetProperty("setupCode").GetString();

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode,
            avatarIdHash = $"avatar-{Guid.NewGuid():N}",
            hudVersion = "security-test"
        });
        response.EnsureSuccessStatusCode();
        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return new HudActivation(
            json.RootElement.GetProperty("deviceId").GetString()!,
            json.RootElement.GetProperty("deviceCredential").GetString()!);
    }

    private sealed record HudActivation(string DeviceId, string DeviceCredential);
}
