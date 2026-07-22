using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.SecondLife;
using HIP.Web.Security;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class LicenseResponsePrivacyTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Test]
    public async Task License_list_and_detail_expose_only_masked_device_references_without_creator_attribution()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var creator = $"stable-license-creator-{Guid.NewGuid():N}";
        var seeded = await CreateAndActivateAsync(factory, creator);
        using var readOnly = Client(factory, AdminRoles.ReadOnly, "license-privacy-reader");

        using var listResponse = await readOnly.GetAsync("/api/v1/licenses/");
        var listBody = await listResponse.Content.ReadAsStringAsync();
        Assert.That(listResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK), listBody);
        var listed = Deserialize<LicenseSummary[]>(listBody)
            .Single(summary => summary.LicenseId == seeded.LicenseId);

        using var detailResponse = await readOnly.GetAsync($"/api/v1/licenses/{seeded.LicenseId}");
        var detailBody = await detailResponse.Content.ReadAsStringAsync();
        Assert.That(detailResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK), detailBody);
        var detail = Deserialize<LicenseSummary>(detailBody);

        Assert.Multiple(() =>
        {
            AssertPrivacySafeSummary(listed, seeded, LicenseStatus.Active);
            AssertPrivacySafeSummary(detail, seeded, LicenseStatus.Active);
            Assert.That(listBody, Does.Not.Contain(seeded.RawDeviceId));
            Assert.That(listBody, Does.Not.Contain(creator));
            Assert.That(detailBody, Does.Not.Contain(seeded.RawDeviceId));
            Assert.That(detailBody, Does.Not.Contain(creator));
        });
    }

    [Test]
    public async Task License_mutation_response_remains_useful_without_disclosing_device_or_creator()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var creator = $"stable-license-creator-{Guid.NewGuid():N}";
        var seeded = await CreateAndActivateAsync(factory, creator);
        using var admin = Client(factory, AdminRoles.Admin, "license-privacy-admin");

        using var response = await admin.PostAsync(
            $"/api/v1/licenses/{seeded.LicenseId}/suspend",
            content: null);
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), body);
        var summary = Deserialize<LicenseSummary>(body);

        Assert.Multiple(() =>
        {
            AssertPrivacySafeSummary(summary, seeded, LicenseStatus.Suspended);
            Assert.That(body, Does.Not.Contain(seeded.RawDeviceId));
            Assert.That(body, Does.Not.Contain(creator));
        });
    }

    private static async Task<SeededLicense> CreateAndActivateAsync(
        HipWebApplicationFactory<Program> factory,
        string creator)
    {
        using var owner = Client(factory, AdminRoles.Owner, creator);
        using var creationResponse = await owner.PostAsJsonAsync(
            "/api/v1/licenses/setup-codes",
            new CreateSetupCodeRequest(1, "forged-creator", "Normal"));
        var creationBody = await creationResponse.Content.ReadAsStringAsync();
        Assert.That(creationResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK), creationBody);
        var creation = Deserialize<CreateSetupCodeResponse>(creationBody);
        Assert.Multiple(() =>
        {
            Assert.That(creation.SetupCode, Is.Not.Empty, "Creation must retain its one-time raw setup code.");
            Assert.That(creation.MaskedSetupCode, Is.Not.EqualTo(creation.SetupCode));
        });

        using var activationResponse = await owner.PostAsJsonAsync(
            "/api/v1/sl-hud/activate",
            new SecondLifeHudActivationRequest(
                creation.SetupCode,
                null,
                $"avatar-{Guid.NewGuid():N}",
                "license-privacy-test"));
        var activationBody = await activationResponse.Content.ReadAsStringAsync();
        Assert.That(activationResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK), activationBody);
        var activation = Deserialize<SecondLifeHudActivationResponse>(activationBody);
        Assert.That(activation.Activated, Is.True);
        Assert.That(activation.DeviceId, Is.Not.Null.And.Not.Empty);

        return new SeededLicense(
            creation.LicenseId,
            creation.MaskedSetupCode,
            activation.DeviceId!);
    }

    private static HttpClient Client(
        HipWebApplicationFactory<Program> factory,
        string role,
        string actor)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, actor);
        return client;
    }

    private static void AssertPrivacySafeSummary(
        LicenseSummary summary,
        SeededLicense seeded,
        LicenseStatus expectedStatus)
    {
        Assert.Multiple(() =>
        {
            Assert.That(summary.LicenseId, Is.EqualTo(seeded.LicenseId));
            Assert.That(summary.MaskedSetupCode, Is.EqualTo(seeded.MaskedSetupCode));
            Assert.That(summary.Status, Is.EqualTo(expectedStatus));
            Assert.That(summary.ActivationCount, Is.EqualTo(1));
            Assert.That(summary.AllowedDeviceCount, Is.EqualTo(1));
            Assert.That(summary.DeviceIds, Is.EqualTo(new[] { MaskDeviceId(seeded.RawDeviceId) }));
            Assert.That(summary.HudVersion, Is.EqualTo("license-privacy-test"));
            Assert.That(summary.CreatedBy, Is.Null);
        });
    }

    private static string MaskDeviceId(string deviceId) =>
        deviceId.Length <= 8 ? "••••" : $"{deviceId[..6]}••••{deviceId[^4..]}";

    private static T Deserialize<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, JsonOptions)
        ?? throw new AssertionException($"Expected a {typeof(T).Name} response body.");

    private sealed record SeededLicense(
        string LicenseId,
        string MaskedSetupCode,
        string RawDeviceId);
}
