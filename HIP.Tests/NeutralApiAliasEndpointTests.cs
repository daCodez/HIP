using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class NeutralApiAliasEndpointTests
{
    [Test]
    public async Task PolicyEvaluate_NeutralAlias_ReturnsOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var request = new JarvisPolicyEvaluationRequestDto(
            IdentityId: "hip-system",
            UserText: "check status",
            ContextNote: "tests",
            ToolName: "status",
            RiskLevel: "low");

        var response = await client.PostAsJsonAsync("/api/policy/evaluate", request);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task TokenAliases_IssueValidateRefreshRevoke_ReturnOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var issue = await client.PostAsJsonAsync("/api/token/issue", new
        {
            identityId = "hip-system",
            audience = "jarvis-runtime",
            deviceId = "device-a"
        });
        Assert.That(issue.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var issuedBody = await issue.Content.ReadAsStringAsync();
        Assert.That(issuedBody, Does.Contain("accessToken"));

        var validate = await client.PostAsJsonAsync("/api/token/validate", new
        {
            accessToken = "invalid",
            audience = "jarvis-runtime",
            deviceId = "device-a"
        });
        Assert.That(validate.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var refresh = await client.PostAsJsonAsync("/api/token/refresh", new { refreshToken = "invalid" });
        Assert.That(refresh.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var revoke = await client.PostAsJsonAsync("/api/token/revoke", new { identityId = "hip-system" });
        Assert.That(revoke.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task ProofAliases_IssueAndConsume_ReturnOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var issue = await client.PostAsJsonAsync("/api/proof/issue", new
        {
            identityId = "hip-system",
            audience = "jarvis-runtime",
            deviceId = "device-a",
            action = "tool:test",
            ttlSeconds = 60
        });

        Assert.That(issue.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var consume = await client.PostAsJsonAsync("/api/proof/consume", new
        {
            proofToken = "invalid",
            expectedAction = "tool:test",
            audience = "jarvis-runtime",
            deviceId = "device-a"
        });

        Assert.That(consume.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}
