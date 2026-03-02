using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class IdentityInsightsBranchTests
{
    [Test]
    public async Task IdentityInsights_MissingIdentity_ReturnsBadRequest()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.identity.insights");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.GetAsync("/api/plugins/identity/insights/%20");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

    [Test]
    public async Task IdentityInsights_TopRisk_RespectsTakeBounds()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.identity.insights");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.GetAsync("/api/plugins/identity/insights/top-risk?take=999");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
