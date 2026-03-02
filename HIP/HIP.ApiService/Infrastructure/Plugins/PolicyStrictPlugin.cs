using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Optional strict policy pack plugin that raises minimum trust thresholds.
/// </summary>
public sealed class PolicyStrictPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.policy.strict",
        Version: "1.0.0",
        Capabilities: ["policy.evaluate"],
        Description: "Raises trust-score thresholds for stricter allow/review/block decisions.");

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.PostConfigure<PolicyPackOptions>(opts =>
        {
            opts.LowRiskRequiredScore = Math.Max(opts.LowRiskRequiredScore, 60);
            opts.MediumRiskRequiredScore = Math.Max(opts.MediumRiskRequiredScore, 90);
            opts.HighRiskRequiredScore = Math.Max(opts.HighRiskRequiredScore, 95);
        });
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/policy/strict", () => Results.Ok(new
            {
                pluginId = Manifest.Id,
                version = Manifest.Version,
                thresholds = new { low = 60, medium = 90, high = 95 }
            }))
            .WithName("GetStrictPolicyPack")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);
    }
}
