using HIP.ApiService.Application.Abstractions;
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
/// Plugin providing identity trust/risk insights from audit and reputation data.
/// </summary>
public sealed class IdentityInsightsPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.identity.insights",
        Version: "1.0.0",
        Capabilities: ["identity.insights.read"],
        Description: "Shows trust/risk insights per identity and top risk identities.",
        NavItems:
        [
            new HipPluginNavItem("Identity Insights", "/identity/insights", "fa-line-chart", 32, "identity.insights.read", "page"),
            new HipPluginNavItem("Risk Identities", "/identity/insights", "fa-exclamation-triangle", 42, "identity.insights.read", "widget")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/identity/insights/{identityId}", HandleIdentityInsightsAsync)
            .WithName("GetIdentityInsights")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest);

        endpoints.MapGet("/api/v1/plugins/identity/insights/{identityId}", HandleIdentityInsightsAsync)
            .WithName("GetIdentityInsightsV1")
            .WithTags("Plugins", "v1")
            .Produces(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest);

        endpoints.MapGet("/api/plugins/identity/insights/top-risk", HandleTopRiskAsync)
            .WithName("GetTopRiskIdentities")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapGet("/api/v1/plugins/identity/insights/top-risk", HandleTopRiskAsync)
            .WithName("GetTopRiskIdentitiesV1")
            .WithTags("Plugins", "v1")
            .Produces(StatusCodes.Status200OK);
    }

    private static async Task<IResult> HandleIdentityInsightsAsync(
        string identityId,
        HipDbContext db,
        IReputationService reputationService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(identityId))
        {
            return Results.BadRequest(new { code = "identity.required" });
        }

        var exists = await db.Identities.AsNoTracking().AnyAsync(x => x.Id == identityId, cancellationToken);
        var score = await reputationService.GetScoreAsync(identityId, cancellationToken);

        var recentRows = await db.AuditEvents
            .AsNoTracking()
            .Where(x => x.Subject == identityId)
            .ToListAsync(cancellationToken);

        var recent = recentRows
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(50)
            .ToList();

        var recentPolicy = recent
            .Where(x => x.EventType == "jarvis.policy.evaluate")
            .Take(10)
            .Select(x => new
            {
                utc = x.CreatedAtUtc,
                outcome = x.Outcome,
                reasonCode = x.ReasonCode
            })
            .ToArray();

        var reasonBreakdown = recent
            .GroupBy(x => x.ReasonCode ?? "none")
            .Select(g => new { reasonCode = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .Take(10)
            .ToArray();

        return Results.Ok(new
        {
            identityId,
            exists,
            reputationScore = score,
            recentPolicy,
            reasonBreakdown
        });
    }

    private static async Task<IResult> HandleTopRiskAsync(int? take, HipDbContext db, CancellationToken cancellationToken)
    {
        var max = Math.Clamp(take ?? 10, 1, 50);
        var since = DateTimeOffset.UtcNow.AddHours(-24);

        var rows = await db.AuditEvents
            .AsNoTracking()
            .Where(x => x.EventType == "jarvis.policy.evaluate")
            .ToListAsync(cancellationToken);

        var result = rows
            .Where(x => x.CreatedAtUtc >= since)
            .GroupBy(x => x.Subject)
            .Select(g => new
            {
                identityId = g.Key,
                blocked = g.Count(x => string.Equals(x.Outcome, "block", StringComparison.OrdinalIgnoreCase)),
                review = g.Count(x => string.Equals(x.Outcome, "review", StringComparison.OrdinalIgnoreCase)),
                total = g.Count()
            })
            .OrderByDescending(x => x.blocked)
            .ThenByDescending(x => x.review)
            .ThenByDescending(x => x.total)
            .Take(max)
            .ToArray();

        return Results.Ok(new { windowHours = 24, identities = result });
    }
}
