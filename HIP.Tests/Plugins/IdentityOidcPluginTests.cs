using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class IdentityOidcPluginTests
{
    [Test]
    public async Task OidcPlugin_IssuerAllowlist_DeniesUnknownIssuer()
    {
        const string enabledKey = "HIP__Plugins__Enabled__0";
        const string allowKey = "HIP__IdentityOidc__AllowedIssuers__0";
        var originalEnabled = Environment.GetEnvironmentVariable(enabledKey);
        var originalAllow = Environment.GetEnvironmentVariable(allowKey);
        Environment.SetEnvironmentVariable(enabledKey, "core.identity.oidc");
        Environment.SetEnvironmentVariable(allowKey, "https://trusted.example.com");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.PostAsJsonAsync("/api/plugins/identity/oidc/resolve", new
            {
                issuer = "https://untrusted.example.com",
                subject = "user-1"
            });

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            var body = await response.Content.ReadAsStringAsync();
            Assert.That(body, Does.Contain("oidc.issuerDenied"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(enabledKey, originalEnabled);
            Environment.SetEnvironmentVariable(allowKey, originalAllow);
        }
    }

    [Test]
    public async Task OidcPlugin_HistoryEndpoint_ReturnsEvents()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.identity.oidc");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            await client.PostAsJsonAsync("/api/plugins/identity/oidc/sync", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-hist"
            });

            var resolve = await client.PostAsJsonAsync("/api/plugins/identity/oidc/resolve", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-hist"
            });

            var resolveBody = await resolve.Content.ReadAsStringAsync();
            var marker = "\"identityId\":\"";
            var start = resolveBody.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            Assert.That(start, Is.GreaterThanOrEqualTo(0));
            start += marker.Length;
            var end = resolveBody.IndexOf('"', start);
            var identityId = resolveBody[start..end];

            var history = await client.GetAsync($"/api/plugins/identity/oidc/history/{identityId}");
            Assert.That(history.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            var historyBody = await history.Content.ReadAsStringAsync();
            Assert.That(historyBody, Does.Contain("identity.oidc.resolve"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }

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

            var syncResponse = await client.PostAsJsonAsync("/api/plugins/identity/oidc/sync", new
            {
                issuer = "https://accounts.example.com",
                subject = "user-123"
            });
            Assert.That(syncResponse.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

            var aliasIdentityResponse = await client.GetAsync("/api/identity/user-123");
            Assert.That(aliasIdentityResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));

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
