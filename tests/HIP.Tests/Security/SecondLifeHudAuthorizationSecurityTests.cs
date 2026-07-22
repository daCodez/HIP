using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Web.Security;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

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

    [Test]
    public async Task Every_device_route_rejects_a_credential_bound_to_a_different_device()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateAsync(client);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);
        var otherDevice = $"sl-hud-other-{Guid.NewGuid():N}";
        var requests = new Func<HttpRequestMessage>[]
        {
            () => new HttpRequestMessage(HttpMethod.Post, "/api/v1/sl-hud/scan")
            {
                Content = JsonContent.Create(new { deviceId = otherDevice })
            },
            () => new HttpRequestMessage(HttpMethod.Get, $"/api/v1/sl-hud/settings/{otherDevice}"),
            () => new HttpRequestMessage(HttpMethod.Post, $"/api/v1/sl-hud/settings/{otherDevice}")
            {
                Content = JsonContent.Create(new { deviceId = otherDevice, mode = "Normal" })
            },
            () => new HttpRequestMessage(HttpMethod.Post, "/api/v1/sl-hud/report")
            {
                Content = JsonContent.Create(new { hudDeviceId = otherDevice })
            },
            () => new HttpRequestMessage(HttpMethod.Post, "/api/v1/sl-hud/report-finding")
            {
                Content = JsonContent.Create(new { hudDeviceId = otherDevice })
            }
        };
        var violations = new List<string>();

        foreach (var createRequest in requests)
        {
            using var request = createRequest();
            using var response = await client.SendAsync(request);
            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                violations.Add($"{request.Method} {request.RequestUri} returned {(int)response.StatusCode}.");
            }
        }

        Assert.That(violations, Is.Empty, string.Join(Environment.NewLine, violations));
    }

    [Test]
    public async Task Hud_scan_rejects_a_previously_issued_credential_after_license_suspension()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var activation = await ActivateAsync(client);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "hud-security-test");
        var suspension = await client.PostAsync($"/api/v1/licenses/{activation.LicenseId}/suspend", content: null);
        suspension.EnsureSuccessStatusCode();
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-Role");
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-User");
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", activation.DeviceCredential);

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", new
        {
            deviceId = activation.DeviceId,
            source = "GroupChat",
            messageText = "limited suspicious snippet",
            detectedUrls = Array.Empty<string>(),
            senderHash = "privacy-safe-sender-hash"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Old_credential_cannot_authorize_a_device_reassigned_after_activation_reset()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var deviceId = $"sl-hud-reassignment-{Guid.NewGuid():N}";
        var original = await ActivateAsync(client, deviceId);

        AddAdmin(client);
        var reset = await client.PostAsync($"/api/v1/licenses/{original.LicenseId}/reset", content: null);
        reset.EnsureSuccessStatusCode();
        RemoveAdmin(client);

        var replacement = await ActivateAsync(client, deviceId);
        client.DefaultRequestHeaders.Add("X-HIP-HUD-Credential", original.DeviceCredential);
        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/scan", new
        {
            deviceId,
            source = "GroupChat",
            messageText = "limited suspicious snippet",
            detectedUrls = Array.Empty<string>(),
            senderHash = "privacy-safe-sender-hash"
        });

        Assert.Multiple(() =>
        {
            Assert.That(replacement.DeviceCredential, Is.Not.EqualTo(original.DeviceCredential));
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        });
    }

    [Test]
    public async Task Invalid_device_id_is_rejected_before_consuming_the_license_device_slot()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var setup = await CreateSetupCodeAsync(client);

        var invalid = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode = setup.SetupCode,
            hudDeviceId = new string('x', 129),
            avatarIdHash = "privacy-safe-avatar-hash",
            hudVersion = "security-test"
        });
        var valid = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode = setup.SetupCode,
            hudDeviceId = $"sl-hud-valid-{Guid.NewGuid():N}",
            avatarIdHash = "privacy-safe-avatar-hash",
            hudVersion = "security-test"
        });

        Assert.Multiple(() =>
        {
            Assert.That(invalid.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(valid.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });
    }

    [Test]
    public async Task Anonymous_hud_activation_has_rate_and_request_size_limits()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoint = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(candidate =>
                candidate.RoutePattern.RawText == "/api/v1/sl-hud/activate" &&
                candidate.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains("POST") == true);

        Assert.Multiple(() =>
        {
            Assert.That(
                endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName,
                Is.EqualTo(RateLimitPolicies.PublicScanPolicy));
            Assert.That(
                endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize,
                Is.LessThanOrEqualTo(16 * 1024));
        });
    }

    private static async Task<HudActivation> ActivateAsync(HttpClient client, string? deviceId = null)
    {
        var setup = await CreateSetupCodeAsync(client);

        var response = await client.PostAsJsonAsync("/api/v1/sl-hud/activate", new
        {
            setupCode = setup.SetupCode,
            hudDeviceId = deviceId,
            avatarIdHash = $"avatar-{Guid.NewGuid():N}",
            hudVersion = "security-test"
        });
        response.EnsureSuccessStatusCode();
        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return new HudActivation(
            setup.LicenseId,
            json.RootElement.GetProperty("deviceId").GetString()!,
            json.RootElement.GetProperty("deviceCredential").GetString()!);
    }

    private static async Task<HudSetupCode> CreateSetupCodeAsync(HttpClient client)
    {
        AddAdmin(client);
        var setupCodeResponse = await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "hud-security-test",
            initialScanMode = "Normal"
        });
        setupCodeResponse.EnsureSuccessStatusCode();
        using var setupCodeJson = await JsonDocument.ParseAsync(await setupCodeResponse.Content.ReadAsStreamAsync());
        var setupCode = setupCodeJson.RootElement.GetProperty("setupCode").GetString();
        var licenseId = setupCodeJson.RootElement.GetProperty("licenseId").GetString()!;
        RemoveAdmin(client);
        return new HudSetupCode(licenseId, setupCode!);
    }

    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "hud-security-test");
    }

    private static void RemoveAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-Role");
        client.DefaultRequestHeaders.Remove("X-HIP-Admin-User");
    }

    private sealed record HudSetupCode(string LicenseId, string SetupCode);
    private sealed record HudActivation(string LicenseId, string DeviceId, string DeviceCredential);
}
