using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Plugin exposing system CPU and memory telemetry for dashboard widgets.
/// </summary>
public sealed class SystemMetricsPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.metrics.system",
        Version: "1.0.0",
        Capabilities: ["metrics.system.read"],
        Description: "Provides CPU and memory usage timeseries for dashboard widgets.",
        NavItems:
        [
            new HipPluginNavItem("CPU Usage", "/", "fa-microchip", 40, "metrics.system.read", "widget"),
            new HipPluginNavItem("Memory Usage", "/", "fa-memory", 41, "metrics.system.read", "widget")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddSingleton<SystemMetricsStore>();
        services.AddHostedService<SystemMetricsSamplerService>();
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/system-metrics", (int? take, SystemMetricsStore store) =>
            {
                var samples = store.GetRecent(take ?? 60);
                return Results.Ok(new
                {
                    samples = samples.Select(x => new { utc = x.Utc, cpu = x.CpuPercent, memory = x.MemoryPercent })
                });
            })
            .WithName("GetSystemMetrics")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);
    }
}
