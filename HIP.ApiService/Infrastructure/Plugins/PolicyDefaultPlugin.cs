using HIP.ApiService.Application.Abstractions;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Core default policy pack plugin.
/// </summary>
public sealed class PolicyDefaultPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.policy.default",
        Version: "1.0.0",
        Capabilities: ["policy.evaluate"],
        Description: "Registers the default policy evaluator for allow/review/block decisions.",
        NavItems:
        [
            new HipPluginNavItem("Policy Pack", "/audit", "fa-balance-scale", 30, "policy.evaluate", "widget")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.Configure<PolicyPackOptions>(configuration.GetSection(PolicyPackOptions.SectionName));
        services.AddScoped<IJarvisPolicyEvaluator, DefaultJarvisPolicyEvaluator>();
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapPost("/api/admin/policy/audit-change", async (PolicyChangeAuditRequest request, HIP.Audit.Abstractions.IAuditTrail auditTrail, CancellationToken ct) =>
            {
                await auditTrail.AppendAsync(new HIP.Audit.Models.AuditEvent(
                    Id: Guid.NewGuid().ToString("n"),
                    CreatedAtUtc: DateTimeOffset.UtcNow,
                    EventType: "policy.config.change",
                    Subject: request.Actor ?? "admin",
                    Source: "admin",
                    Detail: request.Detail ?? "policy settings updated",
                    Category: "policy",
                    Outcome: "success",
                    ReasonCode: "policy.configChanged"), ct);

                return Results.Ok(new { recorded = true });
            })
            .WithName("RecordPolicyChangeAudit")
            .WithTags("Admin", "Policy")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapGet("/api/plugins/policy/current", () =>
            {
                var options = new PolicyPackOptions();
                configuration.GetSection(PolicyPackOptions.SectionName).Bind(options);

                var enabled = configuration.GetSection("HIP:Plugins:Enabled").Get<string[]>() ?? [];
                var source = enabled.Contains("core.policy.strict", StringComparer.OrdinalIgnoreCase)
                    ? "strict"
                    : "default";

                return Results.Ok(new
                {
                    pluginId = Manifest.Id,
                    version = Manifest.Version,
                    source,
                    requiredScores = new
                    {
                        low = options.LowRiskRequiredScore,
                        medium = options.MediumRiskRequiredScore,
                        high = options.HighRiskRequiredScore
                    }
                });
            })
            .WithName("GetCurrentPolicyPack")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);

        endpoints.MapGet("/api/policy/effective", () =>
            {
                var options = new PolicyPackOptions();
                configuration.GetSection(PolicyPackOptions.SectionName).Bind(options);
                var enabled = configuration.GetSection("HIP:Plugins:Enabled").Get<string[]>() ?? [];
                var source = enabled.Contains("core.policy.strict", StringComparer.OrdinalIgnoreCase)
                    ? "strict"
                    : "default";

                return Results.Ok(new
                {
                    source,
                    requiredScores = new
                    {
                        low = options.LowRiskRequiredScore,
                        medium = options.MediumRiskRequiredScore,
                        high = options.HighRiskRequiredScore
                    }
                });
            })
            .WithName("GetEffectivePolicy")
            .WithTags("Policy")
            .Produces(StatusCodes.Status200OK);
    }

    private sealed record PolicyChangeAuditRequest(string? Actor, string? Detail);
}
