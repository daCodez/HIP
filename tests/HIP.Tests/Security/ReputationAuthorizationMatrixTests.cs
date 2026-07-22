using System.Net;
using System.Net.Http.Json;
using HIP.Domain.Reputation;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class ReputationAuthorizationMatrixTests
{
    private const string ManagePolicy = "CanManageReputation";
    private const string ManagePermission = "Reputation.Manage";
    private const string NoRole = "(authenticated-no-role)";

    [Test]
    public async Task Reputation_management_policy_and_permission_are_owner_admin_only()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var policyProvider = factory.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await policyProvider.GetPolicyAsync(ManagePolicy);

        Assert.That(
            typeof(AdminPolicies).GetField(ManagePolicy)?.GetRawConstantValue(),
            Is.EqualTo(ManagePolicy));
        Assert.That(
            typeof(AdminPermissions).GetField("ReputationManage")?.GetRawConstantValue(),
            Is.EqualTo(ManagePermission));
        Assert.That(policy, Is.Not.Null, $"Expected policy '{ManagePolicy}'.");

        var roles = policy!.Requirements
            .OfType<RolesAuthorizationRequirement>()
            .SelectMany(requirement => requirement.AllowedRoles)
            .ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(roles, Is.EquivalentTo(new[] { AdminRoles.Owner, AdminRoles.Admin }));
            Assert.That(
                policy.Requirements.Count(requirement => requirement is PrivilegedMfaRequirement),
                Is.EqualTo(1));
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Owner, ManagePermission), Is.True);
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Admin, ManagePermission), Is.True);
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Moderator, ManagePermission), Is.False);
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.Support, ManagePermission), Is.False);
            Assert.That(AdminRoleCatalog.HasPermission(AdminRoles.ReadOnly, ManagePermission), Is.False);
        });
    }

    [Test]
    public async Task Reputation_routes_publish_view_and_privileged_mutation_metadata()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?.StartsWith(
                "/api/v1/admin/reputation",
                StringComparison.Ordinal) is true)
            .ToArray();

        var profile = Find(endpoints, HttpMethods.Get, "/api/v1/admin/reputation/{targetType}/{targetId}");
        var events = Find(endpoints, HttpMethods.Post, "/api/v1/admin/reputation/events");
        var recalculate = Find(
            endpoints,
            HttpMethods.Post,
            "/api/v1/admin/reputation/{targetType}/{targetId}/recalculate");

        Assert.Multiple(() =>
        {
            Assert.That(
                Policies(profile),
                Is.EquivalentTo(new[] { AdminPolicies.CanViewAdminDashboard }));
            Assert.That(
                Policies(events),
                Is.EquivalentTo(new[]
                {
                    AdminPolicies.CanViewAdminDashboard,
                    ManagePolicy,
                    AdminPolicies.RecentPrivilegedAuthentication
                }));
            Assert.That(
                Policies(recalculate),
                Is.EquivalentTo(new[]
                {
                    AdminPolicies.CanViewAdminDashboard,
                    ManagePolicy,
                    AdminPolicies.RecentPrivilegedAuthentication
                }));
        });
    }

    [Test]
    public async Task Reputation_api_enforces_the_view_and_mutation_role_matrix()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var target = $"reputation-authz-{Guid.NewGuid():N}.example";
        var profilePath = $"/api/v1/admin/reputation/Domain/{target}";
        var recalculatePath = $"{profilePath}/recalculate";

        using (var anonymous = Client(factory))
        {
            Assert.That(await GetStatusAsync(anonymous, profilePath), Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(await EventStatusAsync(anonymous, target), Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(await PostStatusAsync(anonymous, recalculatePath), Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        using (var noRole = Client(factory, NoRole))
        {
            Assert.That(await GetStatusAsync(noRole, profilePath), Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(await EventStatusAsync(noRole, target), Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(await PostStatusAsync(noRole, recalculatePath), Is.EqualTo(HttpStatusCode.Forbidden));
        }

        foreach (var role in new[] { AdminRoles.Moderator, AdminRoles.Support, AdminRoles.ReadOnly })
        {
            using var client = Client(factory, role);
            Assert.That(await GetStatusAsync(client, profilePath), Is.EqualTo(HttpStatusCode.OK), $"{role}:view");
            Assert.That(await EventStatusAsync(client, target), Is.EqualTo(HttpStatusCode.Forbidden), $"{role}:event");
            Assert.That(await PostStatusAsync(client, recalculatePath), Is.EqualTo(HttpStatusCode.Forbidden), $"{role}:recalculate");
        }

        foreach (var role in new[] { AdminRoles.Owner, AdminRoles.Admin })
        {
            using var client = Client(factory, role);
            Assert.That(await GetStatusAsync(client, profilePath), Is.EqualTo(HttpStatusCode.OK), $"{role}:view");
            Assert.That(await EventStatusAsync(client, target), Is.EqualTo(HttpStatusCode.OK), $"{role}:event");
            Assert.That(await PostStatusAsync(client, recalculatePath), Is.EqualTo(HttpStatusCode.OK), $"{role}:recalculate");
        }
    }

    private static RouteEndpoint Find(
        IEnumerable<RouteEndpoint> endpoints,
        string method,
        string routePattern) =>
        endpoints.Single(endpoint =>
            string.Equals(endpoint.RoutePattern.RawText, routePattern, StringComparison.Ordinal) &&
            endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method) is true);

    private static string[] Policies(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(metadata => metadata.Policy)
            .Where(policy => !string.IsNullOrWhiteSpace(policy))
            .Cast<string>()
            .ToArray();

    private static HttpClient Client(HipWebApplicationFactory<Program> factory, string? role = null)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (role is null)
        {
            return client;
        }

        if (string.Equals(role, NoRole, StringComparison.Ordinal))
        {
            client.DefaultRequestHeaders.Add(
                HipDevHeaderAuthenticationHandler.ConsumerHeaderName,
                "reputation-no-role-test");
            return client;
        }

        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(
            HipDevHeaderAuthenticationHandler.UserHeaderName,
            $"{role.ToLowerInvariant()}-reputation-matrix");
        return client;
    }

    private static async Task<HttpStatusCode> GetStatusAsync(HttpClient client, string path)
    {
        using var response = await client.GetAsync(path);
        return response.StatusCode;
    }

    private static async Task<HttpStatusCode> PostStatusAsync(HttpClient client, string path)
    {
        using var response = await client.PostAsync(path, content: null);
        return response.StatusCode;
    }

    private static async Task<HttpStatusCode> EventStatusAsync(HttpClient client, string target)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/v1/admin/reputation/events",
            new ReputationEvent(
                $"reputation-authz-{Guid.NewGuid():N}",
                ReputationSubjectType.Domain,
                target,
                ReputationEventType.ManualCorrection,
                ReputationEventSeverity.Low,
                1,
                ReporterTrustLevel.Admin,
                "Focused authorization matrix test.",
                DateTimeOffset.UtcNow,
                null,
                true,
                false));
        return response.StatusCode;
    }
}
