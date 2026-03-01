using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class IdentityOidcPluginTests
{
    [Test]
    public async Task OidcPlugin_ResolveAndSync_WorksWhenEnabled()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.identity.oidc");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var resolveResponse = await client.PostAsJsonAsync("/api/plugins/identity/oidc/resolve", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-123",
                email = "user@example.com",
                emailVerified = true
            });

            Assert.That(resolveResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            var resolveBody = await resolveResponse.Content.ReadAsStringAsync();
            Assert.That(resolveBody, Does.Contain("oidc-"));
            Assert.That(resolveBody, Does.Contain("\"exists\":false"));

            var syncResponse = await client.PostAsJsonAsync("/api/plugins/identity/oidc/sync", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-123"
            });
            Assert.That(syncResponse.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

            var resolveAgain = await client.PostAsJsonAsync("/api/plugins/identity/oidc/resolve", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-123"
            });

            var resolveAgainBody = await resolveAgain.Content.ReadAsStringAsync();
            Assert.That(resolveAgain.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(resolveAgainBody, Does.Contain("\"exists\":true"));

            var audit = await client.GetFromJsonAsync<List<AuditEvent>>("/api/admin/audit?take=20&eventType=identity.oidc.sync");
            Assert.That(audit, Is.Not.Null);
            Assert.That(audit!.Any(x => x.ReasonCode == "oidc.synced"), Is.True);
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
