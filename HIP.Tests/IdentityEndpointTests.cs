using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class IdentityEndpointTests
{
    [Test]
    public async Task GetIdentity_KnownId_Returns200AndPayload()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/identity/hip-system");
        var payload = await response.Content.ReadFromJsonAsync<IdentityDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Id, Is.EqualTo("hip-system"));
        Assert.That(payload.PublicKeyRef, Is.EqualTo("pkref:placeholder"));
    }

    [Test]
    public async Task GetIdentity_UnknownId_Returns404()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/identity/unknown-id");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
    }
    [Test]
    public async Task GetIdentity_WhitespaceId_Returns400()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/identity/%20");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task GetIdentity_InvalidCharacters_Returns400()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/identity/hip-system!bad");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task GetIdentity_BffOriginWithoutSignature_Returns401()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/identity/hip-system");
        request.Headers.Add("x-hip-origin", "bff");

        using var client = app.CreateClient();
        var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

}
