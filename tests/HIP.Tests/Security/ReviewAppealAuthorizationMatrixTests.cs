using System.Net;
using System.Net.Http.Json;
using HIP.Application.Review;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Web.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Security;

/// <summary>
/// Verifies review and appeal viewing is independent from decision authority across every admin role.
/// </summary>
[TestFixture]
public sealed class ReviewAppealAuthorizationMatrixTests
{
    private const string ViewReviews = "CanViewReviews";
    private const string DecideReviews = "CanDecideReviews";
    private const string ViewAppeals = "CanViewAppeals";
    private const string DecideAppeals = "CanDecideAppeals";
    private const string NoRole = "(authenticated-no-role)";

    [Test]
    public async Task Named_policies_match_the_role_catalog_view_and_decision_permissions()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var provider = factory.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            [ViewReviews] = [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.Support, AdminRoles.ReadOnly],
            [DecideReviews] = [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator],
            [ViewAppeals] = [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator, AdminRoles.ReadOnly],
            [DecideAppeals] = [AdminRoles.Owner, AdminRoles.Admin, AdminRoles.Moderator]
        };

        foreach (var item in expected)
        {
            var policy = await provider.GetPolicyAsync(item.Key);
            Assert.That(policy, Is.Not.Null, item.Key);
            var roles = policy!.Requirements
                .OfType<RolesAuthorizationRequirement>()
                .SelectMany(requirement => requirement.AllowedRoles)
                .ToArray();
            Assert.That(roles, Is.EquivalentTo(item.Value), item.Key);
        }
    }

    [Test]
    public async Task Every_review_and_appeal_route_publishes_view_or_decision_policy_metadata()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .ToArray();

        Assert.Multiple(() =>
        {
            AssertGroupPolicies(endpoints, "/api/v1/admin/review/", ViewReviews, DecideReviews, 2, 6);
            AssertGroupPolicies(endpoints, "/api/v1/admin/review-queue/", ViewReviews, DecideReviews, 2, 3);
            AssertGroupPolicies(endpoints, "/api/v1/admin/appeals/", ViewAppeals, DecideAppeals, 2, 4);
            AssertPolicy(endpoints, HttpMethods.Get, "/api/v1/admin/review/", ViewReviews);
            AssertPolicy(endpoints, HttpMethods.Post, "/api/v1/admin/review/", DecideReviews);
            AssertPolicy(endpoints, HttpMethods.Get, "/api/v1/admin/review-queue/", ViewReviews);
            AssertPolicy(endpoints, HttpMethods.Post, "/api/v1/admin/review-queue/{id}/dismiss", DecideReviews);
            AssertPolicy(endpoints, HttpMethods.Get, "/api/v1/admin/appeals/", ViewAppeals);
            AssertPolicy(endpoints, HttpMethods.Post, "/api/v1/admin/appeals/{id}/approve", DecideAppeals);
            AssertPolicy(endpoints, HttpMethods.Get, "/api/v1/admin/reports", ViewReviews);
        });
    }

    private static void AssertGroupPolicies(
        IReadOnlyCollection<RouteEndpoint> endpoints,
        string routePrefix,
        string viewPolicy,
        string decisionPolicy,
        int expectedGetCount,
        int expectedPostCount)
    {
        var group = endpoints
            .Where(item => item.RoutePattern.RawText?.StartsWith(routePrefix, StringComparison.Ordinal) is true)
            .ToArray();
        var getEndpoints = group.Where(item =>
            item.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(HttpMethods.Get) is true).ToArray();
        var postEndpoints = group.Where(item =>
            item.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(HttpMethods.Post) is true).ToArray();

        Assert.That(getEndpoints, Has.Length.EqualTo(expectedGetCount), $"{routePrefix}:GET count");
        Assert.That(postEndpoints, Has.Length.EqualTo(expectedPostCount), $"{routePrefix}:POST count");
        foreach (var endpoint in getEndpoints)
        {
            Assert.That(Policies(endpoint), Is.EquivalentTo(new[] { viewPolicy }), endpoint.RoutePattern.RawText);
        }

        foreach (var endpoint in postEndpoints)
        {
            Assert.That(Policies(endpoint), Is.EquivalentTo(new[] { decisionPolicy }), endpoint.RoutePattern.RawText);
        }
    }

    [Test]
    public async Task Review_and_appeal_routes_enforce_the_complete_admin_role_matrix()
    {
        await using var factory = new HipWebApplicationFactory<Program>();

        await AssertRoleAsync(factory, role: null, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized);
        await AssertRoleAsync(factory, NoRole, HttpStatusCode.Forbidden, HttpStatusCode.Forbidden, HttpStatusCode.Forbidden);
        await AssertRoleAsync(factory, AdminRoles.Support, HttpStatusCode.OK, HttpStatusCode.Forbidden, HttpStatusCode.Forbidden);
        await AssertRoleAsync(factory, AdminRoles.ReadOnly, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.Forbidden);
        await AssertRoleAsync(factory, AdminRoles.Moderator, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK);
        await AssertRoleAsync(factory, AdminRoles.Admin, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK);
        await AssertRoleAsync(factory, AdminRoles.Owner, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK);
    }

    private static async Task AssertRoleAsync(
        HipWebApplicationFactory<Program> factory,
        string? role,
        HttpStatusCode expectedReviewView,
        HttpStatusCode expectedAppealView,
        HttpStatusCode expectedDecision)
    {
        using var client = Client(factory, role);
        using var reviewView = await client.GetAsync("/api/v1/admin/review/");
        using var appealView = await client.GetAsync("/api/v1/admin/appeals/");
        using var createReview = await client.PostAsJsonAsync(
            "/api/v1/admin/review/",
            ReviewItemFor(role ?? "anonymous"));
        var appealId = await CreateAppealAsync(factory, role ?? "anonymous");
        using var decideAppeal = await client.PostAsJsonAsync(
            $"/api/v1/admin/appeals/{appealId}/approve",
            new { ActorId = "forged-reviewer", Reason = "Privacy-safe matrix decision." });

        Assert.Multiple(() =>
        {
            Assert.That(reviewView.StatusCode, Is.EqualTo(expectedReviewView), $"{role}:review-view");
            Assert.That(appealView.StatusCode, Is.EqualTo(expectedAppealView), $"{role}:appeal-view");
            Assert.That(createReview.StatusCode, Is.EqualTo(expectedDecision), $"{role}:review-decide");
            Assert.That(decideAppeal.StatusCode, Is.EqualTo(expectedDecision), $"{role}:appeal-decide");
        });
    }

    private static ReviewItem ReviewItemFor(string suffix) =>
        new(
            string.Empty,
            ReviewType.RiskyDomain,
            TargetType.Domain,
            $"review-matrix-{Guid.NewGuid():N}.example",
            "Authorization matrix review",
            "Privacy-safe route authorization evidence.",
            RiskStatus.Unknown,
            ReviewStatus.Submitted,
            ReviewPriority.Medium,
            default,
            default,
            $"forged-{suffix}",
            null,
            "authorization-matrix",
            "Privacy-safe evidence only.",
            new Dictionary<string, string> { ["signal"] = "authorization-matrix" },
            "Review the evidence.",
            null,
            null);

    private static async Task<string> CreateAppealAsync(
        HipWebApplicationFactory<Program> factory,
        string suffix)
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync(
            "/api/v1/public/appeals",
            new AppealRequest(
                string.Empty,
                TargetType.Domain,
                $"appeal-matrix-{Guid.NewGuid():N}.example",
                $"sha256:{suffix}",
                "Privacy-safe remediation summary.",
                AppealStatus.Submitted,
                default,
                default,
                null,
                null,
                null,
                new Dictionary<string, string> { ["summary"] = "remediated" }));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AppealRequest>())!.AppealId;
    }

    private static void AssertPolicy(
        IEnumerable<RouteEndpoint> endpoints,
        string method,
        string route,
        string expectedPolicy)
    {
        var endpoint = endpoints.Single(item =>
            string.Equals(item.RoutePattern.RawText, route, StringComparison.Ordinal) &&
            item.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.Contains(method) is true);
        Assert.That(Policies(endpoint), Is.EquivalentTo(new[] { expectedPolicy }), $"{method} {route}");
    }

    private static string?[] Policies(RouteEndpoint endpoint) =>
        endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>()
            .Select(item => item.Policy)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToArray();

    private static HttpClient Client(HipWebApplicationFactory<Program> factory, string? role)
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
                "review-matrix-no-role");
            return client;
        }

        client.DefaultRequestHeaders.Add(HipDevHeaderAuthenticationHandler.RoleHeaderName, role);
        client.DefaultRequestHeaders.Add(
            HipDevHeaderAuthenticationHandler.UserHeaderName,
            $"{role.ToLowerInvariant()}-review-matrix");
        return client;
    }
}
