using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class AdminReputationBreakdownEndpointTests
{
    [Test]
    public async Task AdminReputationBreakdown_ReturnsScoreFactors()
    {
        await using var app = new WebApplicationFactory<Program>();

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HipDbContext>();
            var rec = await db.ReputationSignals.FindAsync("hip-system");
            if (rec is not null)
            {
                rec.AcceptanceRatio = 0.9;
                rec.FeedbackScore = 0.8;
                rec.DaysActive = 365;
                rec.AbuseReports = 1;
                rec.AuthFailures = 0;
                rec.SpamFlags = 0;
                await db.SaveChangesAsync();
            }

            db.ReputationEvents.Add(new ReputationEventRecord
            {
                IdentityId = "hip-system",
                EventType = "policy_blocked",
                CreatedAtUtc = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        using var client = app.CreateClient();
        var response = await client.GetAsync("/api/admin/reputation/hip-system/breakdown");
        var payload = await response.Content.ReadFromJsonAsync<ReputationScoreBreakdown>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.IdentityId, Is.EqualTo("hip-system"));
        Assert.That(payload.EventCount, Is.GreaterThanOrEqualTo(1));
        Assert.That(payload.EventPenaltyComponent, Is.GreaterThan(0));
    }

    [Test]
    public async Task AdminReputationBreakdown_FieldsAreInternallyConsistent()
    {
        await using var app = new WebApplicationFactory<Program>();

        using var client = app.CreateClient();
        var response = await client.GetAsync("/api/admin/reputation/hip-system/breakdown");
        var payload = await response.Content.ReadFromJsonAsync<ReputationScoreBreakdown>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Score, Is.GreaterThanOrEqualTo(0));
        Assert.That(payload.Score, Is.LessThanOrEqualTo(100));
        Assert.That(payload.EventCount, Is.GreaterThanOrEqualTo(0));
        Assert.That(payload.AggregatePenaltyComponent, Is.GreaterThanOrEqualTo(0));
        Assert.That(payload.EventPenaltyComponent, Is.GreaterThanOrEqualTo(0));
    }
}
