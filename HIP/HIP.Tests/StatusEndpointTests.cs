using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Features.Status;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class StatusEndpointTests
{
    [Test]
    public async Task GetStatus_Returns200()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/status");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task GetStatus_ReturnsHip_AndValidTimestamp()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var payload = await client.GetFromJsonAsync<StatusResponse>("/api/status");

        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.ServiceName, Is.EqualTo("HIP"));
        Assert.That(payload.UtcTimestamp, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow));
        Assert.That(payload.UtcTimestamp, Is.GreaterThan(DateTimeOffset.UtcNow.AddMinutes(-1)));
    }

    [Test]
    public async Task GetHealth_Returns200()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}
