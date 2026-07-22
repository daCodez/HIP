using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.SecondLife;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using HIP.Web.Security;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class LicensePrivilegedActionTests
{
    private const string AuthenticatedActor = "authenticated-license-owner";

    private static readonly IReadOnlyDictionary<string, string[]> ExpectedRoutePolicies =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["/api/v1/licenses/"] = [AdminPolicies.CanViewLicenses],
            ["/api/v1/licenses/{licenseId}"] = [AdminPolicies.CanViewLicenses],
            ["/api/v1/licenses/{licenseId}/reset"] = [AdminPolicies.CanSupportLicenses],
            ["/api/v1/licenses/setup-codes"] =
                [AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication],
            ["/api/v1/licenses/{licenseId}/revoke"] =
                [AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication],
            ["/api/v1/licenses/{licenseId}/suspend"] =
                [AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication],
            ["/api/v1/licenses/{licenseId}/reactivate"] =
                [AdminPolicies.CanAdministerLicenses, AdminPolicies.RecentPrivilegedAuthentication]
        };

    /// <summary>
    /// Confirms each license route carries only the least-privilege policy set for its operation.
    /// </summary>
    [Test]
    public async Task License_routes_publish_the_least_privilege_authorization_matrix()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?.StartsWith("/api/v1/licenses", StringComparison.Ordinal) is true)
            .ToDictionary(endpoint => endpoint.RoutePattern.RawText!, StringComparer.Ordinal);

        Assert.Multiple(() =>
        {
            foreach (var expected in ExpectedRoutePolicies)
            {
                Assert.That(endpoints, Does.ContainKey(expected.Key), $"Expected license endpoint '{expected.Key}'.");
                Assert.That(Policies(endpoints[expected.Key]), Is.EquivalentTo(expected.Value), expected.Key);
            }
        });
    }

    /// <summary>
    /// Confirms direct interactive license mutations fail closed before invoking the license service
    /// and provide an explicit route to the step-up flow.
    /// </summary>
    [Test]
    public void Interactive_license_mutations_require_recent_authentication_before_service_calls()
    {
        var root = RepositoryRoot();
        var createPage = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Web", "Components", "Pages", "AdminLicenseNew.razor"));
        var detailPage = File.ReadAllText(Path.Combine(
            root, "src", "HIP.Web", "Components", "Pages", "AdminLicenseDetail.razor"));
        var create = Section(createPage, "private async Task CreateCodeAsync()", "private async Task<string?> RequireRecentActorAsync()");
        var createActorGate = Section(createPage, "private async Task<string?> RequireRecentActorAsync()", "\n}");
        var updateStatus = Section(detailPage, "private async Task UpdateStatusAsync", "private async Task AllowNewDeviceAsync()");
        var allowDevice = Section(detailPage, "private async Task AllowNewDeviceAsync()", "private async Task<bool> RequirePolicyAsync");

        Assert.Multiple(() =>
        {
            AssertGateBeforeMutation(create, "RequireRecentActorAsync", "LicenseService.CreateSetupCode");
            AssertGateBeforeMutation(updateStatus, "AdminPolicies.CanAdministerLicenses", "LicenseService.SetStatus");
            AssertGateBeforeMutation(updateStatus, "AdminPolicies.RecentPrivilegedAuthentication", "LicenseService.SetStatus");
            AssertGateBeforeMutation(allowDevice, "AdminPolicies.CanSupportLicenses", "LicenseService.ResetActivation");
            Assert.That(allowDevice, Does.Not.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(createActorGate, Does.Contain("AdminPolicies.CanAdministerLicenses"));
            Assert.That(createPage, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(detailPage, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(createPage, Does.Contain("href=\"@StepUpHref\""));
            Assert.That(detailPage, Does.Contain("href=\"@StepUpHref\""));
            Assert.That(create, Does.Not.Contain("\"admin-ui\""));
            Assert.That(createActorGate, Does.Contain("HipAuthenticationClaimTypes.ActorId"));
            Assert.That(createActorGate, Does.Contain("HostEnvironment.IsDevelopment()"));
        });
    }

    /// <summary>
    /// Confirms caller-supplied creator metadata cannot spoof the actor persisted with a setup-code license.
    /// </summary>
    [Test]
    public async Task Setup_code_api_ignores_forged_creator_and_persists_authenticated_actor()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminRoles.Owner);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", AuthenticatedActor);

        var createResponse = await client.PostAsJsonAsync(
            "/api/v1/licenses/setup-codes",
            new CreateSetupCodeRequest(1, "forged-license-creator", "Normal"));
        var created = await ReadSuccessfulResponseAsync<CreateSetupCodeResponse>(createResponse);
        await using var scope = factory.Services.CreateAsyncScope();
        var persisted = scope.ServiceProvider
            .GetRequiredService<ISetupCodeLicenseService>()
            .GetLicense(created.LicenseId);

        Assert.That(PersistedCreator(persisted), Is.EqualTo(AuthenticatedActor));
    }

    /// <summary>
    /// Confirms the in-memory implementation carries creator attribution into its persisted summary.
    /// </summary>
    [Test]
    public void In_memory_license_service_persists_creator_attribution()
    {
        var service = new InMemorySetupCodeLicenseService();
        var created = service.CreateSetupCode(new CreateSetupCodeRequest(1, AuthenticatedActor, "Normal"));

        var persisted = service.GetLicense(created.LicenseId);

        Assert.That(PersistedCreator(persisted), Is.EqualTo(AuthenticatedActor));
    }

    /// <summary>
    /// Confirms setup-code records written before creator attribution was added remain readable with a null creator.
    /// </summary>
    [Test]
    public void Legacy_license_json_without_creator_remains_readable()
    {
        var creatorProperty = typeof(SetupCodeLicense).GetProperty("CreatedBy");
        Assert.That(creatorProperty, Is.Not.Null, "SetupCodeLicense must expose backward-compatible creator attribution.");
        var legacyJson = JsonSerializer.Serialize(new
        {
            LicenseId = "lic-legacy",
            SetupCode = "HIP-LEGACY-CODE",
            Status = LicenseStatus.Pending,
            AllowedDeviceCount = 1,
            DeviceIds = Array.Empty<string>(),
            AvatarIdHash = (string?)null,
            ActivatedAtUtc = (DateTimeOffset?)null,
            LastSeenAtUtc = (DateTimeOffset?)null,
            HudVersion = (string?)null,
            Settings = new LicenseHudSettings("Normal", true, true, true)
        });

        var legacy = JsonSerializer.Deserialize<SetupCodeLicense>(legacyJson);

        Assert.That(legacy, Is.Not.Null);
        Assert.That(creatorProperty!.GetValue(legacy), Is.Null);
    }

    private static string? PersistedCreator(object? license) =>
        license?.GetType().GetProperty("CreatedBy")?.GetValue(license) as string;

    private static async Task<T> ReadSuccessfulResponseAsync<T>(HttpResponseMessage response)
        where T : class
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.IsSuccessStatusCode, Is.True, body);
        return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new AssertionException($"Expected a {typeof(T).Name} response body.");
    }

    private static string[] Policies(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(metadata => metadata.Policy)
            .Where(policy => !string.IsNullOrWhiteSpace(policy))
            .Cast<string>()
            .ToArray();

    private static void AssertGateBeforeMutation(string source, string gate, string mutation)
    {
        var gateIndex = source.IndexOf(gate, StringComparison.Ordinal);
        var mutationIndex = source.IndexOf(mutation, StringComparison.Ordinal);
        Assert.That(gateIndex, Is.GreaterThanOrEqualTo(0), $"Expected gate '{gate}'.");
        Assert.That(mutationIndex, Is.GreaterThan(gateIndex), $"Expected '{gate}' before '{mutation}'.");
    }

    private static string Section(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.That(start, Is.GreaterThanOrEqualTo(0), $"Could not find '{startMarker}'.");
        var end = source.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        Assert.That(end, Is.GreaterThan(start), $"Could not find '{endMarker}' after '{startMarker}'.");
        return source[start..end];
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
