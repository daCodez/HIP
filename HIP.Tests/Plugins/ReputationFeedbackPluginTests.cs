using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.ApiService.Infrastructure.Plugins;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Plugins;

public sealed class ReputationFeedbackPluginTests
{
    [Test]
    public async Task FeedbackPlugin_SubmitAndStats_WorksWhenEnabled()
    {
        const string key = "HIP__Plugins__Enabled__0";
        var original = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, "core.reputation.feedback");

        try
        {
            await using var app = new WebApplicationFactory<Program>();
            using var client = app.CreateClient();

            var response = await client.PostAsJsonAsync("/api/plugins/reputation/feedback",
                new ReputationFeedbackPlugin.ReputationFeedbackRequest("beta-node", "malicious", "email", "phishing"));

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Accepted));

            var stats = await client.GetAsync("/api/plugins/reputation/feedback/stats");
            var statsBody = await stats.Content.ReadAsStringAsync();
            Assert.That(stats.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(statsBody, Does.Contain("malicious"));

            var audit = await client.GetFromJsonAsync<List<AuditEvent>>("/api/admin/audit?take=20&eventType=reputation.feedback.submit");
            Assert.That(audit, Is.Not.Null);
            Assert.That(audit!.Any(x => x.ReasonCode == "feedback.malicious"), Is.True);

            using var scope = app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<HipDbContext>();
            var signal = await db.ReputationSignals.FindAsync("beta-node");
            Assert.That(signal, Is.Not.Null);
            Assert.That(signal!.AbuseReports, Is.GreaterThanOrEqualTo(1));
        }
        finally
        {
            Environment.SetEnvironmentVariable(key, original);
        }
    }
}
