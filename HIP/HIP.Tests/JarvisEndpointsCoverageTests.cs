using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class JarvisEndpointsCoverageTests
{
    [Test]
    public async Task JarvisAndNeutralEndpoints_BasicFlow_ReturnsOk()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        // Context aliases
        Assert.That((await client.GetAsync("/api/jarvis/context/hip-system")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.GetAsync("/api/identity/context/hip-system")).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var toolReq = new JarvisToolAccessRequestDto("hip-system", "status", "low");
        Assert.That((await client.PostAsJsonAsync("/api/jarvis/tool-access", toolReq)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/policy/tool-access", toolReq)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var policyReq = new JarvisPolicyEvaluationRequestDto("hip-system", "check status", "tests", "status", "low");
        Assert.That((await client.PostAsJsonAsync("/api/jarvis/policy/evaluate", policyReq)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/policy/evaluate", policyReq)).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        // Token/proof aliases
        var issue = await client.PostAsJsonAsync("/api/token/issue", new { identityId = "hip-system", audience = "jarvis-runtime", deviceId = "device-z" });
        Assert.That(issue.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var issueBody = await issue.Content.ReadAsStringAsync();
        Assert.That(issueBody, Does.Contain("accessToken"));

        Assert.That((await client.PostAsJsonAsync("/api/jarvis/token/validate", new { accessToken = "invalid", audience = "jarvis-runtime", deviceId = "device-z" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/token/validate", new { accessToken = "invalid", audience = "jarvis-runtime", deviceId = "device-z" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That((await client.PostAsJsonAsync("/api/jarvis/token/refresh", new { refreshToken = "invalid" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/token/refresh", new { refreshToken = "invalid" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That((await client.PostAsJsonAsync("/api/jarvis/token/revoke", new { identityId = "hip-system" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/token/revoke", new { identityId = "hip-system" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That((await client.PostAsJsonAsync("/api/jarvis/proof/issue", new { identityId = "hip-system", audience = "jarvis-runtime", deviceId = "device-z", action = "tool:test", ttlSeconds = 60 })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/proof/issue", new { identityId = "hip-system", audience = "jarvis-runtime", deviceId = "device-z", action = "tool:test", ttlSeconds = 60 })).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That((await client.PostAsJsonAsync("/api/jarvis/proof/consume", new { proofToken = "invalid", expectedAction = "tool:test", audience = "jarvis-runtime", deviceId = "device-z" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await client.PostAsJsonAsync("/api/proof/consume", new { proofToken = "invalid", expectedAction = "tool:test", audience = "jarvis-runtime", deviceId = "device-z" })).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}
