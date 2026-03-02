using HIP.Audit.Abstractions;
using HIP.ApiService.Infrastructure.Audit;
using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Core plugin that provides the default durable database-backed audit trail.
/// </summary>
public sealed class AuditDatabasePlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.audit.database",
        Version: "1.0.0",
        Capabilities: ["audit.trail.write", "audit.trail.read"],
        Description: "Registers DatabaseAuditTrail as the default audit sink.",
        NavItems:
        [
            new HipPluginNavItem("Audit", "/audit", "fa-shield", 20, "audit.trail.read")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddScoped<IAuditTrail, DatabaseAuditTrail>();
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        // No plugin-specific endpoints required.
    }
}
