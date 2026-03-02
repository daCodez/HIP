using System.Linq;
using System.Net;
using System.Net.Http.Json;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AuditFilteringTests
{
    [Test]
    public async Task GetAuditEvents_FiltersByEventType()
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

        await client.GetAsync("/api/identity/hip-system");
        await client.GetAsync("/api/reputation/hip-system");

        var response = await client.GetAsync("/api/admin/audit?take=20&eventType=identity.read");
        var payload = await response.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!, Is.Not.Empty);
        Assert.That(payload!.All(x => x.EventType == "identity.read"), Is.True);
    }
}
