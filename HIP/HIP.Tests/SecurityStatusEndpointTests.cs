using System.Net;
using System.Net.Http.Json;
using HIP.ApiService.Application.Abstractions;
using HIP.ApiService.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests;

public sealed class SecurityStatusEndpointTests
{
    [Test]
    public async Task SecurityStatus_ReturnsCountersSnapshot()
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

            var counters = scope.ServiceProvider.GetRequiredService<ISecurityEventCounter>();
            counters.IncrementReplayDetected();
            counters.IncrementMessageExpired();
            counters.IncrementPolicyBlocked();
        }

        using var client = app.CreateClient();
        var response = await client.GetAsync("/api/admin/security-status");
        var payload = await response.Content.ReadFromJsonAsync<SecurityStatusDto>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(payload, Is.Not.Null);
        Assert.That(payload!.ReplayDetected, Is.GreaterThanOrEqualTo(1));
        Assert.That(payload.MessageExpired, Is.GreaterThanOrEqualTo(1));
        Assert.That(payload.PolicyBlocked, Is.GreaterThanOrEqualTo(1));
    }

    private sealed record SecurityStatusDto(long ReplayDetected, long MessageExpired, long PolicyBlocked, DateTimeOffset UtcTimestamp);
}
