using System.Net.Http.Json;
using HIP.Application.Platforms;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies platform administration keeps read access separate from actor-bound, recently authorized mutations.
/// </summary>
[TestFixture]
public sealed class PlatformAdministrationSecurityTests
{
    /// <summary>
    /// Confirms platform reads retain the dashboard-view policy while both mutations add management and recent-auth gates.
    /// </summary>
    [Test]
    public async Task Platform_routes_publish_view_and_privileged_mutation_policies()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.RoutePattern.RawText?.StartsWith(
                "/api/v1/admin/platforms",
                StringComparison.Ordinal) is true)
            .ToArray();

        var list = Find(endpoints, HttpMethods.Get, "/api/v1/admin/platforms/");
        var discord = Find(endpoints, HttpMethods.Get, "/api/v1/admin/platforms/discord");
        var connect = Find(endpoints, HttpMethods.Post, "/api/v1/admin/platforms/discord/connect");
        var disable = Find(endpoints, HttpMethods.Post, "/api/v1/admin/platforms/discord/disable");

        Assert.Multiple(() =>
        {
            Assert.That(Policies(list), Is.EquivalentTo(new[] { AdminPolicies.CanViewAdminDashboard }));
            Assert.That(Policies(discord), Is.EquivalentTo(new[] { AdminPolicies.CanViewAdminDashboard }));
            Assert.That(
                Policies(connect),
                Is.EquivalentTo(new[]
                {
                    AdminPolicies.CanViewAdminDashboard,
                    AdminPolicies.CanManagePlatforms,
                    AdminPolicies.RecentPrivilegedAuthentication
                }));
            Assert.That(
                Policies(disable),
                Is.EquivalentTo(new[]
                {
                    AdminPolicies.CanViewAdminDashboard,
                    AdminPolicies.CanManagePlatforms,
                    AdminPolicies.RecentPrivilegedAuthentication
                }));
        });
    }

    /// <summary>
    /// Confirms connect and disable persistence use the authenticated HIP actor rather than caller-controlled data.
    /// </summary>
    [Test]
    public async Task Platform_mutations_persist_the_authenticated_HIP_actor()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var owner = AdminClient(factory, AdminRoles.Owner, "platform-owner");
        using var administrator = AdminClient(factory, AdminRoles.Admin, "platform-administrator");

        using var connectResponse = await owner.PostAsJsonAsync(
            "/api/v1/admin/platforms/discord/connect",
            new ConnectDiscordPlatformRequest(
                "123456789012345678",
                "HIP platform security test",
                "223456789012345678",
                "323456789012345678",
                null,
                null));
        var connected = await ReadDiscordRecordAsync(factory.Services);

        using var disableResponse = await administrator.PostAsync(
            "/api/v1/admin/platforms/discord/disable",
            content: null);
        var disabled = await ReadDiscordRecordAsync(factory.Services);

        Assert.Multiple(() =>
        {
            Assert.That(connectResponse.IsSuccessStatusCode, Is.True);
            Assert.That(connected?.UpdatedBy, Is.EqualTo("platform-owner"));
            Assert.That(disableResponse.IsSuccessStatusCode, Is.True);
            Assert.That(disabled?.UpdatedBy, Is.EqualTo("platform-administrator"));
            Assert.That(disabled?.Status, Is.EqualTo(HipPlatformConnectionStatus.Disabled));
        });
    }

    /// <summary>
    /// Confirms interactive-server mutations are hidden from viewers and reauthorize a unique current actor before service calls.
    /// </summary>
    [Test]
    public void Platform_page_uses_actor_bound_immediate_reauthorization_without_fallback()
    {
        var page = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "HIP.Web",
            "Components",
            "Pages",
            "AdminPlatformConnections.razor"));
        var guard = Section(page, "private async Task<bool> RunAuthorizedPlatformMutationAsync", "private async Task DisableDiscordAsync");

        Assert.Multiple(() =>
        {
            Assert.That(page, Does.Contain("Authorize(Policy = AdminPolicies.CanViewAdminDashboard)"));
            Assert.That(page, Does.Contain("Policy=\"@AdminPolicies.CanManagePlatforms\""));
            Assert.That(page, Does.Contain("AuthenticationStateProvider"));
            Assert.That(page, Does.Contain("AuthorizationService"));
            Assert.That(page, Does.Contain("HipAdminPageAccess.ExecuteAuthorizedAsync"));
            Assert.That(page, Does.Not.Contain("local-admin"));
            Assert.That(guard, Does.Contain("AdminPolicies.CanManagePlatforms"));
            Assert.That(guard, Does.Contain("AdminPolicies.RecentPrivilegedAuthentication"));
            Assert.That(
                guard.IndexOf("AuthorizationService.AuthorizeAsync", StringComparison.Ordinal),
                Is.LessThan(guard.IndexOf("HipAdminPageAccess.ExecuteAuthorizedAsync", StringComparison.Ordinal)));
            Assert.That(page, Does.Contain("RunAuthorizedPlatformMutationAsync(actor =>\n                PlatformConnectionService.ConnectDiscordAsync"));
            Assert.That(page, Does.Contain("RunAuthorizedPlatformMutationAsync(actor =>\n                PlatformConnectionService.DisableDiscordAsync"));
        });
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

    private static HttpClient AdminClient(
        HipWebApplicationFactory<Program> factory,
        string role,
        string actor)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.UserHeaderName, actor);
        return client;
    }

    private static async Task<PlatformConnectionRecord?> ReadDiscordRecordAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPlatformConnectionRepository>();
        return await repository.GetAsync(PlatformConnectionService.DiscordConnectionId, CancellationToken.None);
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
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("Could not locate the HIP repository root.");
    }
}
