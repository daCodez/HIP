using System.Net;
using System.Net.Http.Json;
using HIP.Application.SecondLife;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class LicenseAuthorizationMatrixTests
{
    private const string NoRole = "(authenticated-no-role)";

    private static readonly IReadOnlyDictionary<string, string[]> ExpectedPolicyRoles =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            [AdminPolicies.CanViewLicenses] =
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support, AdminRoles.ReadOnly],
            [AdminPolicies.CanSupportLicenses] =
                [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Support],
            [AdminPolicies.CanAdministerLicenses] =
                [AdminRoles.Owner, AdminRoles.Admin]
        };

    /// <summary>
    /// Confirms the named license policies expose the exact least-privilege role sets and retain HIP's
    /// privileged-session assurance requirement for Owner and Admin principals.
    /// </summary>
    [Test]
    public async Task Named_license_policies_define_the_expected_role_matrix()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var policyProvider = factory.Services.GetRequiredService<IAuthorizationPolicyProvider>();

        foreach (var expected in ExpectedPolicyRoles)
        {
            var policy = await policyProvider.GetPolicyAsync(expected.Key);
            Assert.That(policy, Is.Not.Null, $"Expected policy '{expected.Key}'.");
            var roles = policy!.Requirements
                .OfType<RolesAuthorizationRequirement>()
                .SelectMany(requirement => requirement.AllowedRoles)
                .ToArray();

            Assert.Multiple(() =>
            {
                Assert.That(roles, Is.EquivalentTo(expected.Value), expected.Key);
                Assert.That(
                    policy.Requirements.Count(requirement => requirement is PrivilegedMfaRequirement),
                    Is.EqualTo(1),
                    expected.Key);
            });
        }
    }

    /// <summary>
    /// Confirms anonymous requests receive 401 while authenticated principals outside each route's role set
    /// receive 403, and every allowed role reaches the intended handler.
    /// </summary>
    [Test]
    public async Task License_api_enforces_the_role_matrix_with_correct_401_and_403_semantics()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var actual = new Dictionary<string, HttpStatusCode>(StringComparer.Ordinal);

        using (var anonymous = Client(factory))
        {
            actual["Anonymous:view"] = await StatusAsync(anonymous, HttpMethod.Get, "/api/v1/licenses/");
            actual["Anonymous:detail"] = await StatusAsync(anonymous, HttpMethod.Get, "/api/v1/licenses/lic-missing");
        }

        foreach (var role in new[] { NoRole, AdminRoles.Moderator })
        {
            using var client = Client(factory, role);
            actual[$"{role}:view"] = await StatusAsync(client, HttpMethod.Get, "/api/v1/licenses/");
            actual[$"{role}:detail"] = await StatusAsync(client, HttpMethod.Get, "/api/v1/licenses/lic-missing");
        }

        using (var readOnly = Client(factory, AdminRoles.ReadOnly))
        {
            actual["ReadOnly:view"] = await StatusAsync(readOnly, HttpMethod.Get, "/api/v1/licenses/");
            actual["ReadOnly:detail"] = await StatusAsync(readOnly, HttpMethod.Get, "/api/v1/licenses/lic-missing");
            actual["ReadOnly:create"] = await CreateStatusAsync(readOnly);
            actual["ReadOnly:reset"] = await StatusAsync(readOnly, HttpMethod.Post, "/api/v1/licenses/lic-missing/reset");
            actual["ReadOnly:suspend"] = await StatusAsync(readOnly, HttpMethod.Post, "/api/v1/licenses/lic-missing/suspend");
        }

        using (var support = Client(factory, AdminRoles.Support))
        {
            actual["Support:view"] = await StatusAsync(support, HttpMethod.Get, "/api/v1/licenses/");
            actual["Support:detail"] = await StatusAsync(support, HttpMethod.Get, "/api/v1/licenses/lic-missing");
            actual["Support:create"] = await CreateStatusAsync(support);
            actual["Support:reset"] = await StatusAsync(support, HttpMethod.Post, "/api/v1/licenses/lic-missing/reset");
            actual["Support:suspend"] = await StatusAsync(support, HttpMethod.Post, "/api/v1/licenses/lic-missing/suspend");
        }

        foreach (var role in new[] { AdminRoles.Admin, AdminRoles.Owner })
        {
            using var client = Client(factory, role);
            actual[$"{role}:view"] = await StatusAsync(client, HttpMethod.Get, "/api/v1/licenses/");
            using var creation = await client.PostAsJsonAsync(
                "/api/v1/licenses/setup-codes",
                new CreateSetupCodeRequest(1, "forged-matrix-actor", "Normal"));
            actual[$"{role}:create"] = creation.StatusCode;
            var created = await creation.Content.ReadFromJsonAsync<CreateSetupCodeResponse>();
            Assert.That(created, Is.Not.Null, $"Expected {role} setup-code response.");
            var licenseId = created!.LicenseId;
            actual[$"{role}:detail"] = await StatusAsync(client, HttpMethod.Get, $"/api/v1/licenses/{licenseId}");
            actual[$"{role}:reset"] = await StatusAsync(client, HttpMethod.Post, $"/api/v1/licenses/{licenseId}/reset");
            actual[$"{role}:suspend"] = await StatusAsync(client, HttpMethod.Post, $"/api/v1/licenses/{licenseId}/suspend");
            actual[$"{role}:reactivate"] = await StatusAsync(client, HttpMethod.Post, $"/api/v1/licenses/{licenseId}/reactivate");
            actual[$"{role}:revoke"] = await StatusAsync(client, HttpMethod.Post, $"/api/v1/licenses/{licenseId}/revoke");
        }

        var expected = new Dictionary<string, HttpStatusCode>(StringComparer.Ordinal)
        {
            ["Anonymous:view"] = HttpStatusCode.Unauthorized,
            ["Anonymous:detail"] = HttpStatusCode.Unauthorized,
            [$"{NoRole}:view"] = HttpStatusCode.Forbidden,
            [$"{NoRole}:detail"] = HttpStatusCode.Forbidden,
            ["Moderator:view"] = HttpStatusCode.Forbidden,
            ["Moderator:detail"] = HttpStatusCode.Forbidden,
            ["ReadOnly:view"] = HttpStatusCode.OK,
            ["ReadOnly:detail"] = HttpStatusCode.NotFound,
            ["ReadOnly:create"] = HttpStatusCode.Forbidden,
            ["ReadOnly:reset"] = HttpStatusCode.Forbidden,
            ["ReadOnly:suspend"] = HttpStatusCode.Forbidden,
            ["Support:view"] = HttpStatusCode.OK,
            ["Support:detail"] = HttpStatusCode.NotFound,
            ["Support:create"] = HttpStatusCode.Forbidden,
            ["Support:reset"] = HttpStatusCode.NotFound,
            ["Support:suspend"] = HttpStatusCode.Forbidden
        };
        foreach (var role in new[] { AdminRoles.Admin, AdminRoles.Owner })
        {
            expected[$"{role}:view"] = HttpStatusCode.OK;
            expected[$"{role}:create"] = HttpStatusCode.OK;
            expected[$"{role}:detail"] = HttpStatusCode.OK;
            expected[$"{role}:reset"] = HttpStatusCode.OK;
            expected[$"{role}:suspend"] = HttpStatusCode.OK;
            expected[$"{role}:reactivate"] = HttpStatusCode.OK;
            expected[$"{role}:revoke"] = HttpStatusCode.OK;
        }

        Assert.Multiple(() =>
        {
            foreach (var item in expected)
            {
                Assert.That(actual[item.Key], Is.EqualTo(item.Value), item.Key);
            }
        });
    }

    /// <summary>
    /// Confirms rendered license controls and navigation mirror server authorization without treating hidden
    /// controls as the security boundary.
    /// </summary>
    [Test]
    public async Task License_pages_and_navigation_hide_actions_outside_each_role_tier()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var admin = Client(factory, AdminRoles.Admin);
        using var creation = await admin.PostAsJsonAsync(
            "/api/v1/licenses/setup-codes",
            new CreateSetupCodeRequest(1, "forged-page-actor", "Normal"));
        var created = await creation.Content.ReadFromJsonAsync<CreateSetupCodeResponse>();
        Assert.That(created, Is.Not.Null);

        using var readOnly = Client(factory, AdminRoles.ReadOnly);
        using var support = Client(factory, AdminRoles.Support);
        var readOnlyList = await readOnly.GetStringAsync("/admin/licenses");
        var supportList = await support.GetStringAsync("/admin/licenses");
        var adminList = await admin.GetStringAsync("/admin/licenses");
        var readOnlyDetail = await readOnly.GetStringAsync($"/admin/licenses/{created!.LicenseId}");
        var supportDetail = await support.GetStringAsync($"/admin/licenses/{created.LicenseId}");
        var adminDetail = await admin.GetStringAsync($"/admin/licenses/{created.LicenseId}");
        using var readOnlySimulator = await readOnly.GetAsync("/admin/sl-hud-simulator");
        using var supportSimulator = await support.GetAsync("/admin/sl-hud-simulator");
        var simulatorPolicies = typeof(Program).Assembly
            .GetType("HIP.Web.Components.Pages.AdminSecondLifeHudSimulator")!
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .Select(attribute => attribute.Policy);

        Assert.Multiple(() =>
        {
            Assert.That(readOnlyList, Does.Not.Contain("Create a license"));
            Assert.That(readOnlyList, Does.Contain("Licenses"));
            Assert.That(readOnlyList, Does.Not.Contain("HUD Simulator"));
            Assert.That(readOnlyDetail, Does.Not.Contain("Allow a new device"));
            Assert.That(readOnlyDetail, Does.Not.Contain("Pause access"));
            Assert.That(readOnlyDetail, Does.Not.Contain("Cancel this license"));
            Assert.That(supportList, Does.Not.Contain("Create a license"));
            Assert.That(supportList, Does.Contain("HUD Simulator"));
            Assert.That(supportDetail, Does.Contain("Allow a new device"));
            Assert.That(supportDetail, Does.Not.Contain("Pause access"));
            Assert.That(supportDetail, Does.Not.Contain("Cancel this license"));
            Assert.That(adminList, Does.Contain("Create a license"));
            Assert.That(adminDetail, Does.Contain("Allow a new device"));
            Assert.That(adminDetail, Does.Contain("Pause access"));
            Assert.That(adminDetail, Does.Contain("Cancel this license"));
            Assert.That(simulatorPolicies, Does.Contain(AdminPolicies.CanSupportLicenses));
            Assert.That(readOnlySimulator.IsSuccessStatusCode, Is.False);
            Assert.That(supportSimulator.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });
    }

    private static HttpClient Client(HipWebApplicationFactory<Program> factory, string? role = null)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (role is null)
        {
            return client;
        }

        if (string.Equals(role, NoRole, StringComparison.Ordinal))
        {
            client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.ConsumerHeaderName, "license-no-role-test");
            return client;
        }

        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, $"{role.ToLowerInvariant()}-license-matrix");
        return client;
    }

    private static async Task<HttpStatusCode> CreateStatusAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/v1/licenses/setup-codes",
            new CreateSetupCodeRequest(1, "forged-matrix-actor", "Normal"));
        return response.StatusCode;
    }

    private static async Task<HttpStatusCode> StatusAsync(HttpClient client, HttpMethod method, string path)
    {
        using var request = new HttpRequestMessage(method, path);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }
}
