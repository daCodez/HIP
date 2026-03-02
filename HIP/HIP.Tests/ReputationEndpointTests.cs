using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class ReputationEndpointTests
{
    [Test]
    public async Task GetReputation_Returns200AndBaseScore()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/reputation/hip-system");
        var payload = await response.Content.ReadFromJsonAsync<ReputationDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.IdentityId, Is.EqualTo("hip-system"));
        Assert.That(payload.Score, Is.EqualTo(100));
        Assert.That(payload.UtcTimestamp, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow));
    }
    [Test]
    public async Task GetReputation_WhitespaceIdentity_Returns400()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/reputation/%20");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task GetReputation_InvalidCharacters_Returns400()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/reputation/hip-system!bad");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

}
