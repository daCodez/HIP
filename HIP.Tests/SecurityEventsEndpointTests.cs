using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class SecurityEventsEndpointTests
{
    [Test]
    public async Task SecurityEvents_ReturnsRecentRejects_WithClockSkew()
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

            var log = scope.ServiceProvider.GetRequiredService<ISecurityRejectLog>();
            log.Add(new SecurityRejectEvent("replay_detected", "hip-system", "m1", 0.25, "benign_suspected", DateTimeOffset.UtcNow));
        }

        using var client = app.CreateClient();
        var response = await client.GetAsync("/api/admin/security-events?take=10");
        var payload = await response.Content.ReadFromJsonAsync<List<SecurityEventDto>>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.Count, Is.GreaterThanOrEqualTo(1));
        Assert.That(payload[0].Reason, Is.EqualTo("replay_detected"));
        Assert.That(payload[0].ClockSkewSeconds, Is.Not.Null);
    }

    private sealed record SecurityEventDto(string Reason, string IdentityId, string? MessageId, double? ClockSkewSeconds, string? Classification, DateTimeOffset UtcTimestamp);
}
