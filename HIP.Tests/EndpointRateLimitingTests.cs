using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class EndpointRateLimitingTests
{
    private sealed record RateLimitErrorDto(string Code, string Reason, double? RetryAfterSeconds);

    [Test]
    public async Task IdentityEndpoint_EnforcesTighterRateLimit_WithStandard429Body()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        HttpResponseMessage? rejected = null;

        for (var i = 0; i < 25; i++)
        {
            var response = await client.GetAsync($"/api/identity/test-user-{i}");
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                rejected = response;
                break;
            }

            response.Dispose();
        }

        Assert.That(rejected, Is.Not.Null);
        Assert.That(rejected!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));

        var payload = await rejected.Content.ReadFromJsonAsync<RateLimitErrorDto>();
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Code, Is.EqualTo("rateLimit.exceeded"));
        Assert.That(payload.Reason, Is.EqualTo("too many requests"));

        rejected.Dispose();
    }

    [Test]
    public async Task ReputationEndpoint_EnforcesTighterRateLimit_WithStandard429Body()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        HttpResponseMessage? rejected = null;

        for (var i = 0; i < 25; i++)
        {
            var response = await client.GetAsync($"/api/reputation/test-user-{i}");
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                rejected = response;
                break;
            }

            response.Dispose();
        }

        Assert.That(rejected, Is.Not.Null);
        Assert.That(rejected!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));

        var payload = await rejected.Content.ReadFromJsonAsync<RateLimitErrorDto>();
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Code, Is.EqualTo("rateLimit.exceeded"));
        Assert.That(payload.Reason, Is.EqualTo("too many requests"));

        rejected.Dispose();
    }
}
