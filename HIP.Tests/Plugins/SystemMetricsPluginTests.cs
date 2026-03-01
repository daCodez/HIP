using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class SystemMetricsPluginTests
{
    [Test]
    public async Task SystemMetricsPlugin_WhenEnabled_ReturnsSamples()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.metrics.system");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            await Task.Delay(1200);

            var response = await client.GetAsync("/api/plugins/system-metrics?take=10");
            var payload = await response.Content.ReadFromJsonAsync<SystemMetricsDto>();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(payload, Is.Not.Null);
            Assert.That(payload!.Samples.Count, Is.GreaterThan(0));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    private sealed record SystemMetricPointDto(DateTimeOffset Utc, double Cpu, double Memory);
    private sealed record SystemMetricsDto(List<SystemMetricPointDto> Samples);
}
