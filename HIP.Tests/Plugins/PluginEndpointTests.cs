using System.Net;
using System.Net.Http.Json;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class PluginEndpointTests
{
    [Test]
    public async Task GetPlugins_Default_DoesNotIncludeSample()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/plugins");
        var payload = await response.Content.ReadFromJsonAsync<List<HipPluginManifest>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Any(x => x.Id == "sample"), Is.False);
    }

    [Test]
    public async Task GetPlugins_WithSampleEnabled_IncludesSample()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "sample");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.GetAsync("/api/plugins");
            var payload = await response.Content.ReadFromJsonAsync<List<HipPluginManifest>>();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(payload, Is.Not.Null);
            Assert.That(payload!.Any(x => x.Id == "sample"), Is.True);

            var ping = await client.GetAsync("/api/plugins/sample/ping");
            Assert.That(ping.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
