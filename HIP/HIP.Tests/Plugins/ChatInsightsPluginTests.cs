using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class ChatInsightsPluginTests
{
    [Test]
    public async Task ChatInsightsPlugin_WhenEnabled_AnswersQuery()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.chat.insights");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var providers = await client.GetAsync("/api/plugins/chat/providers");
            Assert.That(providers.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var oauthStatus = await client.GetAsync("/api/plugins/chat/oauth/status");
            Assert.That(oauthStatus.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var oauthStart = await client.GetAsync("/api/plugins/chat/oauth/start");
            Assert.That(oauthStart.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));

            var query = await client.PostAsJsonAsync("/api/plugins/chat/query", new { question = "what are top risks?" });
            Assert.That(query.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var body = await query.Content.ReadAsStringAsync();
            Assert.That(body, Does.Contain("answer"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
