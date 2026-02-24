using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class ReputationStressTests
{
    [Test]
    [Category("Stress")]
    public async Task ReputationReads_UnderParallelLoad_ReturnSuccessfulResponses()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        const int totalRequests = 200;
        var stopwatch = Stopwatch.StartNew();

        var tasks = Enumerable.Range(0, totalRequests)
            .Select(_ => client.GetAsync("/api/reputation/hip-system"));

        var responses = await Task.WhenAll(tasks);
        stopwatch.Stop();

        var okCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        var throttledCount = responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests);

        Assert.That(okCount, Is.GreaterThan(0), "Expected successful reputation responses under load.");
        Assert.That(throttledCount, Is.GreaterThan(0), "Expected rate-limited responses under burst load.");

        var okPayloadTasks = responses
            .Where(r => r.StatusCode == HttpStatusCode.OK)
            .Select(r => r.Content.ReadFromJsonAsync<ReputationDto>());
        var payloads = await Task.WhenAll(okPayloadTasks);

        Assert.That(payloads.All(p => p is not null), Is.True);
        Assert.That(payloads.All(p => p!.IdentityId == "hip-system"), Is.True);

        TestContext.WriteLine($"Reputation stress test: {totalRequests} requests in {stopwatch.ElapsedMilliseconds} ms (ok={okCount}, throttled={throttledCount})");
    }
}
