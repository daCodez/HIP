using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

/// <summary>
/// Verifies protected license/setup-code API behavior for the MVP support flow.
/// </summary>
[TestFixture]
public sealed class LicenseApiTests
{
    /// <summary>
    /// Confirms license management APIs require an authorized admin/support role.
    /// </summary>
    [Test]
    public async Task Admin_license_routes_are_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/licenses/");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>
    /// Confirms support users can create setup codes through the protected API.
    /// </summary>
    [Test]
    public async Task Support_can_create_setup_code()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Support");

        var response = await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "support-test",
            initialScanMode = "Normal"
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var payload = await response.Content.ReadFromJsonAsync<CreateSetupCodeApiResponse>();
        Assert.That(payload?.SetupCode, Does.StartWith("HIP-"));
    }

    /// <summary>
    /// Confirms license list responses mask setup codes by default.
    /// </summary>
    [Test]
    public async Task License_list_masks_setup_codes()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Support");

        var created = await (await client.PostAsJsonAsync("/api/v1/licenses/setup-codes", new
        {
            allowedDeviceCount = 1,
            createdBy = "support-test",
            initialScanMode = "Normal"
        })).Content.ReadFromJsonAsync<CreateSetupCodeApiResponse>();

        var list = await client.GetFromJsonAsync<LicenseSummaryApiResponse[]>("/api/v1/licenses/");
        var listed = list!.Single(license => license.LicenseId == created!.LicenseId);

        Assert.That(listed.MaskedSetupCode, Is.Not.EqualTo(created!.SetupCode));
        Assert.That(listed.MaskedSetupCode, Does.Contain("****"));
    }

    /// <summary>
    /// Adds the development admin role headers used by the HIP MVP auth handler.
    /// </summary>
    /// <param name="client">HTTP client.</param>
    /// <param name="role">Role to apply.</param>
    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-license-test");
    }

    /// <summary>
    /// Minimal setup-code API response shape for tests.
    /// </summary>
    /// <param name="LicenseId">Created license ID.</param>
    /// <param name="SetupCode">Raw setup code returned only on creation.</param>
    /// <param name="MaskedSetupCode">Masked setup code.</param>
    private sealed record CreateSetupCodeApiResponse(string LicenseId, string SetupCode, string MaskedSetupCode);

    /// <summary>
    /// Minimal license summary API response shape for tests.
    /// </summary>
    /// <param name="LicenseId">License ID.</param>
    /// <param name="MaskedSetupCode">Masked setup code.</param>
    private sealed record LicenseSummaryApiResponse(string LicenseId, string MaskedSetupCode);
}
