using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class IdentityInsightsPluginTests
{
    [Test]
    public async Task IdentityInsightsPlugin_WhenEnabled_ExposesEndpoints()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.identity.insights");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var topRisk = await client.GetAsync("/api/plugins/identity/insights/top-risk?take=5");
            Assert.That(topRisk.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var perIdentity = await client.GetAsync("/api/plugins/identity/insights/hip-system");
            Assert.That(perIdentity.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
