using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Simple dashboard widget plugin used for UI smoke checks.
/// </summary>
public sealed class RichardWidgetPlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "core.widget.richard",
        Version: "1.0.0",
        Capabilities: ["widget.richard"],
        Description: "Adds a simple Richard widget to the dashboard.",
        NavItems:
        [
            new HipPluginNavItem("Richard", "/api/plugins/widgets/richard", "fa-user", 85, "widget.richard", "widget")
        ]);

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/widgets/richard", () => Results.Ok(new
            {
                name = "Richard",
                message = "Richard"
            }))
            .WithName("GetRichardWidget")
            .WithTags("Plugins")
            .Produces(StatusCodes.Status200OK);
    }
}
