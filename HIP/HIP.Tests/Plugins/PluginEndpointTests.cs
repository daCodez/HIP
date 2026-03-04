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
        Assert.That(payload!.Any(x => x.Id == "core.policy.default"), Is.True);
        Assert.That(payload!.Any(x => x.Id == "core.widget.richard"), Is.True);
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

            var nav = await client.GetFromJsonAsync<List<HipPluginNavItem>>("/api/plugins/nav");
            Assert.That(nav, Is.Not.Null);
            Assert.That(nav!.Any(x => x.Route == "/api/plugins/sample/ping"), Is.True);

            var ping = await client.GetAsync("/api/plugins/sample/ping");
            Assert.That(ping.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    [Test]
    public async Task StrictPolicyPlugin_WhenEnabled_AppearsInPluginList()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.policy.strict");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.GetAsync("/api/plugins");
            var payload = await response.Content.ReadFromJsonAsync<List<HipPluginManifest>>();

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(payload, Is.Not.Null);
            Assert.That(payload!.Any(x => x.Id == "core.policy.strict"), Is.True);

            var strictResponse = await client.GetAsync("/api/plugins/policy/strict");
            Assert.That(strictResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var effective = await client.GetAsync("/api/policy/effective");
            var effectiveBody = await effective.Content.ReadAsStringAsync();
            Assert.That(effective.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(effectiveBody, Does.Contain("\"source\":\"strict\""));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    [Test]
    public async Task PolicyPlugin_CurrentEndpoint_ReturnsDefaultThresholds()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/plugins/policy/current");
        var payload = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Does.Contain("\"pluginId\":\"core.policy.default\""));
        Assert.That(payload, Does.Contain("\"source\":"));
        Assert.That(payload, Does.Contain("\"policyVersion\":"));
        Assert.That(payload, Does.Contain("\"low\":"));
        Assert.That(payload, Does.Contain("\"medium\":50"));
        Assert.That(payload, Does.Contain("\"high\":80"));

        var effective = await client.GetAsync("/api/policy/effective");
        var effectiveBody = await effective.Content.ReadAsStringAsync();
        Assert.That(effective.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(effectiveBody, Does.Contain("\"source\":"));
        Assert.That(effectiveBody, Does.Contain("\"policyVersion\":"));
    }

    [Test]
    public async Task PluginWidgetsEndpoint_ReturnsWidgetItemsOnly()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var response = await client.GetAsync("/api/plugins/widgets");
        var payload = await response.Content.ReadFromJsonAsync<List<HipPluginNavItem>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Any(x => x.Display == "widget"), Is.True);
        Assert.That(payload!.Any(x => x.Label == "Richard"), Is.True);
        Assert.That(payload!.Any(x => x.Display == "page"), Is.False);
    }

    [Test]
    public async Task AutoDiscover_WithAllowlist_LoadsSampleWithoutExplicitEnable()
    {
        const string autoDiscoverKey = "HIP__Plugins__AutoDiscover";
        const string allowlistKey = "HIP__Plugins__Allowlist__0";
        const string enabledKey = "HIP__Plugins__Enabled__0";

        var originalAuto = Environment.GetEnvironmentVariable(autoDiscoverKey);
        var originalAllow = Environment.GetEnvironmentVariable(allowlistKey);
        var originalEnabled = Environment.GetEnvironmentVariable(enabledKey);

        Environment.SetEnvironmentVariable(autoDiscoverKey, "true");
        Environment.SetEnvironmentVariable(allowlistKey, "sample");
        Environment.SetEnvironmentVariable(enabledKey, "sample");

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
            Environment.SetEnvironmentVariable(autoDiscoverKey, originalAuto);
            Environment.SetEnvironmentVariable(allowlistKey, originalAllow);
            Environment.SetEnvironmentVariable(enabledKey, originalEnabled);
        }
    }
}
