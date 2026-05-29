using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Api;

[TestFixture]
public sealed class AdminAuthorizationTests
{
    [Test]
    public async Task Admin_api_requires_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Public_lookup_does_not_require_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/lookup/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Public_badge_does_not_require_auth()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/public/badge/domain/example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Owner_can_access_protected_admin_route()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Owner");

        var response = await client.GetAsync("/api/v1/admin/audit-logs");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Readonly_cannot_approve_override()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "ReadOnly");

        var response = await client.PostAsJsonAsync("/api/v1/admin/reputation-overrides/override-1/approve", new
        {
            ActorId = "readonly",
            Reason = "Should not approve."
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Moderator_can_review_reports()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Moderator");

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Support_cannot_manage_rules()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        AddRole(client, "Support");

        var response = await client.PostAsJsonAsync("/api/v1/admin/rules/simulate", new
        {
            Rule = (object?)null,
            TestCases = Array.Empty<object>()
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Unauthorized_request_is_rejected()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static void AddRole(HttpClient client, string role)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", role);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", $"{role.ToLowerInvariant()}-test-admin");
    }
}
