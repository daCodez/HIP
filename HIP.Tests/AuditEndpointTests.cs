using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Audit;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AuditEndpointTests
{
    [Test]
    public async Task GetAuditEvents_Returns200_AndList()
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
        var response = await client.GetAsync("/api/admin/audit?take=10");
        var payload = await response.Content.ReadFromJsonAsync<List<AuditEvent>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Count, Is.GreaterThanOrEqualTo(1));
    }
}
