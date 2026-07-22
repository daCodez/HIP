using System.Net;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies non-HUD rule, identity, and external-evidence routes have explicit privileged access boundaries.
/// </summary>
[TestFixture]
public sealed class NonHudRouteAuthorizationTests
{
    private static readonly ProtectedRoute[] ProtectedRoutes =
    [
        new(HttpMethods.Get, "/api/v1/rules", "/api/v1/rules", AdminPolicies.CanManageRules),
        new(HttpMethods.Get, "/api/v1/rules/{id}", "/api/v1/rules/new-domain-shortener-high-risk", AdminPolicies.CanManageRules),
        new(HttpMethods.Post, "/api/v1/rules/evaluate", "/api/v1/rules/evaluate", AdminPolicies.CanManageRules),
        new(HttpMethods.Post, "/api/v1/rules/simulate", "/api/v1/rules/simulate", AdminPolicies.CanManageRules),
        new(HttpMethods.Get, "/api/v1/rules/simulations/{id}", "/api/v1/rules/simulations/missing", AdminPolicies.CanManageRules),
        new(HttpMethods.Post, "/api/v1/identity/domain-verification/start", "/api/v1/identity/domain-verification/start", AdminPolicies.CanManageDomainVerifications, RateLimitPolicies.IdentityDevPolicy),
        new(HttpMethods.Post, "/api/v1/identity/domain-verification/verify", "/api/v1/identity/domain-verification/verify", AdminPolicies.CanManageDomainVerifications, RateLimitPolicies.IdentityDevPolicy),
        new(HttpMethods.Post, "/api/v1/identity/register", "/api/v1/identity/register", AdminPolicies.CanManageDomainVerifications, RateLimitPolicies.IdentityDevPolicy),
        new(HttpMethods.Post, "/api/v1/identity/sign", "/api/v1/identity/sign", AdminPolicies.CanManageDomainVerifications, RateLimitPolicies.IdentityDevPolicy),
        new(HttpMethods.Post, "/api/v1/site-safety/external-evidence/check", "/api/v1/site-safety/external-evidence/check", AdminPolicies.CanManageRules, RateLimitPolicies.PublicScanPolicy)
    ];

    /// <summary>
    /// Confirms each route has the intended named authorization policy and retains its existing rate-limit policy.
    /// </summary>
    [Test]
    public async Task Non_hud_routes_have_expected_policy_metadata()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .ToArray();
        var violations = new List<string>();

        foreach (var expected in ProtectedRoutes)
        {
            var matches = endpoints
                .Where(endpoint =>
                    NormalizeRoute(endpoint.RoutePattern.RawText) == NormalizeRoute(expected.Pattern) &&
                    endpoint.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(expected.Method, StringComparer.OrdinalIgnoreCase) == true)
                .ToArray();

            if (matches.Length != 1)
            {
                violations.Add($"{expected.Method} {expected.Pattern} resolved to {matches.Length} endpoints.");
                continue;
            }

            var endpoint = matches[0];
            var policies = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
                .Select(metadata => metadata.Policy)
                .Where(policy => !string.IsNullOrWhiteSpace(policy))
                .ToArray();
            if (!policies.Contains(expected.Policy, StringComparer.Ordinal))
            {
                violations.Add($"{expected.Method} {expected.Pattern} is missing {expected.Policy}.");
            }

            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                violations.Add($"{expected.Method} {expected.Pattern} also allows anonymous access.");
            }

            if (expected.RateLimitPolicy is not null &&
                endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName != expected.RateLimitPolicy)
            {
                violations.Add($"{expected.Method} {expected.Pattern} is missing rate limit {expected.RateLimitPolicy}.");
            }
        }

        Assert.That(violations, Is.Empty, string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// Confirms authorization runs before request binding or endpoint execution for every protected route.
    /// </summary>
    [Test]
    public async Task Non_hud_routes_reject_anonymous_requests()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var violations = new List<string>();

        foreach (var route in ProtectedRoutes)
        {
            using var request = new HttpRequestMessage(new HttpMethod(route.Method), route.RequestPath);
            using var response = await client.SendAsync(request);
            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                violations.Add($"{route.Method} {route.RequestPath} returned {(int)response.StatusCode} instead of 401.");
            }
        }

        Assert.That(violations, Is.Empty, string.Join(Environment.NewLine, violations));
    }

    private static string NormalizeRoute(string? route) =>
        $"/{(route ?? string.Empty).Trim().Trim('/')}";

    private sealed record ProtectedRoute(
        string Method,
        string Pattern,
        string RequestPath,
        string Policy,
        string? RateLimitPolicy = null);
}
