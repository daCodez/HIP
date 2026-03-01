using System.Linq;
using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class TokenAuditTrailTests
{
    [Test]
    public async Task TokenIssue_WritesAuditEvent()
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

        var issueResponse = await client.PostAsJsonAsync("/api/jarvis/token/issue", new
        {
            identityId = "hip-system",
            audience = "jarvis-runtime",
            deviceId = "device-test"
        });

        Assert.That(issueResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var auditResponse = await client.GetAsync("/api/admin/audit?take=20&eventType=jarvis.token.issue");
        var payload = await auditResponse.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(auditResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!, Is.Not.Empty);
        Assert.That(payload!.Any(x => x.EventType == "jarvis.token.issue" && x.Outcome == "success"), Is.True);
    }
}
