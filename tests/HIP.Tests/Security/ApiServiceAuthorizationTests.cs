extern alias ApiServiceAlias;

using System.Net;
using System.Net.Http.Json;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies the standalone API host fails closed around operator-only provider and domain checks.
/// </summary>
[TestFixture]
public sealed class ApiServiceAuthorizationTests
{
    /// <summary>
    /// Confirms every operator-only API-service route challenges an anonymous caller before its handler runs.
    /// </summary>
    [Test]
    public async Task Privileged_api_service_routes_reject_anonymous_callers()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        using var client = factory.CreateClient();

        var providerRead = await client.GetAsync("/api/v1/site-safety/external-providers");
        var providerWrite = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-providers",
            ProviderPreferencePayload());
        var evidenceCheck = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-evidence/check",
            new { Url = "not-a-url" });
        var domainCheck = await client.PostAsJsonAsync(
            "/api/v1/domain-verification/check",
            new { Domain = "", ExpectedToken = "" });

        Assert.Multiple(() =>
        {
            Assert.That(providerRead.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(providerWrite.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(evidenceCheck.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(domainCheck.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        });
    }

    /// <summary>
    /// Confirms local Development principals with the intended roles can reach each protected handler.
    /// </summary>
    [Test]
    public async Task Authorized_local_admin_roles_reach_privileged_api_service_handlers()
    {
        await using var factory = ProviderWritesEnabledFactory();
        using var readOnlyClient = factory.CreateClient();
        AddDevelopmentAdmin(readOnlyClient, AdminRoles.ReadOnly, "api-readonly");
        using var adminClient = factory.CreateClient();
        AddDevelopmentAdmin(adminClient, AdminRoles.Admin, "api-admin");

        var providerRead = await readOnlyClient.GetAsync("/api/v1/site-safety/external-providers");
        var providerWrite = await adminClient.PostAsJsonAsync(
            "/api/v1/site-safety/external-providers",
            ProviderPreferencePayload());
        var evidenceCheck = await adminClient.PostAsJsonAsync(
            "/api/v1/site-safety/external-evidence/check",
            new { Url = "not-a-url" });
        var domainCheck = await adminClient.PostAsJsonAsync(
            "/api/v1/domain-verification/check",
            new { Domain = "", ExpectedToken = "" });

        Assert.Multiple(() =>
        {
            Assert.That(providerRead.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(providerWrite.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(evidenceCheck.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(domainCheck.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        });
    }

    /// <summary>
    /// Confirms dashboard readers cannot invoke provider mutations or active external/domain checks.
    /// </summary>
    [Test]
    public async Task Read_only_role_is_forbidden_from_privileged_api_service_writes_and_checks()
    {
        await using var factory = ProviderWritesEnabledFactory();
        using var client = factory.CreateClient();
        AddDevelopmentAdmin(client, AdminRoles.ReadOnly, "api-readonly");

        var providerWrite = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-providers",
            ProviderPreferencePayload());
        var evidenceCheck = await client.PostAsJsonAsync(
            "/api/v1/site-safety/external-evidence/check",
            new { Url = "not-a-url" });
        var domainCheck = await client.PostAsJsonAsync(
            "/api/v1/domain-verification/check",
            new { Domain = "", ExpectedToken = "" });

        Assert.Multiple(() =>
        {
            Assert.That(providerWrite.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(evidenceCheck.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(domainCheck.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        });
    }

    /// <summary>
    /// Confirms powerful Development headers are ignored when the peer is not direct loopback.
    /// </summary>
    [Test]
    public async Task Development_admin_headers_fail_closed_for_non_loopback_api_service_requests()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>(
            IPAddress.Parse("203.0.113.10"));
        using var client = factory.CreateClient();
        AddDevelopmentAdmin(client, AdminRoles.Admin, "api-admin");

        var response = await client.GetAsync("/api/v1/site-safety/external-providers");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    /// <summary>
    /// Pins API-service route metadata to the maintained Web policy names until the routes are consolidated.
    /// </summary>
    [Test]
    public async Task Privileged_api_service_routes_use_the_same_named_policies_as_web()
    {
        await using var factory = new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .ToArray();

        AssertPolicies(
            endpoints,
            HttpMethods.Get,
            "/api/v1/site-safety/external-providers",
            AdminPolicies.CanViewAdminDashboard);
        AssertPolicies(
            endpoints,
            HttpMethods.Post,
            "/api/v1/site-safety/external-providers",
            AdminPolicies.CanManageRules,
            AdminPolicies.RecentPrivilegedAuthentication);
        AssertPolicies(
            endpoints,
            HttpMethods.Post,
            "/api/v1/site-safety/external-evidence/check",
            "CanCheckExternalSiteEvidence");
        AssertPolicies(
            endpoints,
            HttpMethods.Post,
            "/api/v1/domain-verification/check",
            "CanCheckDomainVerification");
    }

    private static Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceAlias::ApiServiceProgram>
        ProviderWritesEnabledFactory() =>
        new HipWebApplicationFactory<ApiServiceAlias::ApiServiceProgram>()
            .WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["HipSecurity:AllowClientProviderPreferenceWrites"] = "true"
                })));

    private static void AddDevelopmentAdmin(HttpClient client, string role, string actor)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", actor);
    }

    private static void AssertPolicies(
        IReadOnlyCollection<RouteEndpoint> endpoints,
        string method,
        string route,
        params string[] expectedPolicies)
    {
        var endpoint = endpoints.Single(item =>
            string.Equals($"/{item.RoutePattern.RawText?.TrimStart('/')}", route, StringComparison.Ordinal) &&
            item.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method, StringComparer.Ordinal) == true);
        var actualPolicies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(item => item.Policy)
            .Where(policy => !string.IsNullOrWhiteSpace(policy))
            .Cast<string>()
            .ToArray();

        Assert.That(actualPolicies, Is.EquivalentTo(expectedPolicies), $"Unexpected policies for {method} {route}.");
    }

    private static object ProviderPreferencePayload() => new
    {
        ExternalProvidersEnabled = false,
        AllowFullUrlChecks = false,
        SslLabs = new { Enabled = false },
        GoogleWebRisk = new { Enabled = false },
        VirusTotal = new { Enabled = false }
    };
}
