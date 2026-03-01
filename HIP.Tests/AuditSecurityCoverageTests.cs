using System.Linq;
using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AuditSecurityCoverageTests
{
    [Test]
    public async Task AuditQuery_CanFilterByOutcomeAndReasonCode_ForTokenValidationFailures()
    {
        await using var app = new WebApplicationFactory<Program>();
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HipDbContext>();
            var rec = await db.ReputationSignals.FindAsync("hip-system");
            if (rec is not null)
            {
                rec.AcceptanceRatio = 1;
                rec.FeedbackScore = 1;
                rec.DaysActive = 365;
                rec.AbuseReports = 0;
                rec.AuthFailures = 0;
                rec.SpamFlags = 0;
                await db.SaveChangesAsync();
            }
        }

        using var client = app.CreateClient();

        var validateResponse = await client.PostAsJsonAsync("/api/jarvis/token/validate", new
        {
            accessToken = "v1.invalid.payload",
            audience = "jarvis-runtime",
            deviceId = "device-test"
        });

        Assert.That(validateResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var auditResponse = await client.GetAsync("/api/admin/audit?take=20&eventType=jarvis.token.validate&outcome=fail&reasonCode=invalid_token");
        var payload = await auditResponse.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(auditResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!, Is.Not.Empty);
        Assert.That(payload!.All(x => x.EventType == "jarvis.token.validate"), Is.True);
        Assert.That(payload!.All(x => x.Outcome == "fail"), Is.True);
        Assert.That(payload!.All(x => x.ReasonCode == "invalid_token"), Is.True);
    }

    [Test]
    public async Task RateLimitRejections_AreWrittenToAuditTrail()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        for (var i = 0; i < 30; i++)
        {
            await client.GetAsync($"/api/identity/test-{i}");
        }

        var auditResponse = await client.GetAsync("/api/admin/audit?take=50&eventType=api.rate_limit.rejected&reasonCode=rateLimit.exceeded");
        var payload = await auditResponse.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(auditResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!, Is.Not.Empty);
        Assert.That(payload!.Any(x => x.Outcome == "throttled"), Is.True);
    }
}
