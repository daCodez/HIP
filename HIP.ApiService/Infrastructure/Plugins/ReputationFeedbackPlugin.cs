using HIP.Audit.Abstractions;
using HIP.Audit.Models;
using HIP.ApiService.Infrastructure.Persistence;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Plugin that ingests recipient feedback signals and updates reputation records.
/// </summary>
public sealed class ReputationFeedbackPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.reputation.feedback",
        Version: "1.0.0",
        Capabilities: ["reputation.feedback.write", "reputation.feedback.read"],
        Description: "Collects recipient feedback and applies it to reputation signals.",
        NavItems:
        [
            new HipPluginNavItem("Feedback", "/feedback", "fa-comments-o", 95, "reputation.feedback.read")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapPost("/api/plugins/reputation/feedback", HandleFeedbackAsync)
            .RequireRateLimiting("read-api")
            .WithName("SubmitReputationFeedback")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status202Accepted)
            .Produces(StatusCodes.Status400BadRequest);

        endpoints.MapGet("/api/plugins/reputation/feedback/stats", HandleStatsAsync)
            .RequireRateLimiting("read-api")
            .WithName("GetReputationFeedbackStats")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);
    }

    private static async Task<IResult> HandleFeedbackAsync(
        ReputationFeedbackRequest request,
        HipDbContext db,
        IAuditTrail auditTrail,
        CancellationToken cancellationToken)
    {
        var identityId = request.IdentityId?.Trim();
        var feedback = request.Feedback?.Trim().ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Results.BadRequest(new { code = "feedback.identityRequired" });
        }

        if (feedback is not ("legit" or "suspicious" or "malicious"))
        {
            return Results.BadRequest(new { code = "feedback.invalidType", allowed = new[] { "legit", "suspicious", "malicious" } });
        }

        var now = DateTimeOffset.UtcNow;
        var record = await db.ReputationSignals.FirstOrDefaultAsync(x => x.IdentityId == identityId, cancellationToken);
        if (record is null)
        {
            record = new ReputationSignalRecord
            {
                IdentityId = identityId,
                AcceptanceRatio = 0,
                FeedbackScore = 0,
                DaysActive = 0,
                AbuseReports = 0,
                AuthFailures = 0,
                SpamFlags = 0,
                UpdatedAtUtc = now
            };
            db.ReputationSignals.Add(record);
        }

        switch (feedback)
        {
            case "legit":
                record.FeedbackScore = Clamp01(record.FeedbackScore + 0.08);
                record.AcceptanceRatio = Clamp01(record.AcceptanceRatio + 0.05);
                break;
            case "suspicious":
                record.FeedbackScore = Clamp01(record.FeedbackScore - 0.06);
                record.AuthFailures += 1;
                break;
            case "malicious":
                record.FeedbackScore = Clamp01(record.FeedbackScore - 0.15);
                record.AbuseReports += 1;
                record.SpamFlags += 1;
                break;
        }

        record.UpdatedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);

        await auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: now,
            EventType: "reputation.feedback.submit",
            Subject: identityId,
            Source: "api",
            Detail: feedback,
            Category: "reputation",
            Outcome: "accepted",
            ReasonCode: $"feedback.{feedback}"), cancellationToken);

        return Results.Accepted(value: new { accepted = true, identityId, feedback });
    }

    private static async Task<IResult> HandleStatsAsync(HipDbContext db, CancellationToken cancellationToken)
    {
        var since = DateTimeOffset.UtcNow.AddHours(-24);

        var rows = await db.AuditEvents
            .AsNoTracking()
            .Where(x => x.EventType == "reputation.feedback.submit")
            .ToListAsync(cancellationToken);

        var grouped = rows
            .Where(x => x.CreatedAtUtc >= since)
            .GroupBy(x => x.Detail)
            .Select(g => new { feedback = g.Key, count = g.Count() })
            .ToList();

        return Results.Ok(new
        {
            windowHours = 24,
            counts = grouped,
            total = grouped.Sum(x => x.count)
        });
    }

    private static double Clamp01(double value) => Math.Max(0, Math.Min(1, value));

    /// <summary>
    /// Feedback submission payload.
    /// </summary>
    public sealed record ReputationFeedbackRequest(string IdentityId, string Feedback, string? Source = null, string? Note = null);
}
