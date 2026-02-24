using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class JarvisIntegrationEndpointTests
{
    [Test]
    public async Task GetJarvisContext_KnownIdentity_ReturnsTrustContext()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/jarvis/context/hip-system");
        var payload = await response.Content.ReadFromJsonAsync<JarvisTrustContextDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.IdentityId, Is.EqualTo("hip-system"));
        Assert.That(payload.IdentityExists, Is.True);
        Assert.That(payload.ReputationScore, Is.InRange(0, 100));
        Assert.That(payload.TrustLevel, Is.EqualTo("medium"));
        Assert.That(payload.MemoryRoute, Is.EqualTo("constrained"));
    }

    [Test]
    public async Task EvaluateToolAccess_HighRiskUnknownIdentity_ReturnsDenied()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var request = new JarvisToolAccessRequestDto("unknown-id", "nodes.camera_snap", "high");
        var response = await client.PostAsJsonAsync("/api/jarvis/tool-access", request);
        var payload = await response.Content.ReadFromJsonAsync<JarvisToolAccessResultDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Allowed, Is.False);
        Assert.That(payload.Reason, Is.EqualTo("identity_not_found"));
        Assert.That(payload.RequiredScore, Is.EqualTo(80));
    }
}
