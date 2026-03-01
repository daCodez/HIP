using HIP.Plugins.Abstractions.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.Plugins.Sample;

/// <summary>
/// Minimal sample plugin used to validate plugin registration/loading flow.
/// </summary>
public sealed class SamplePlugin : IHipPlugin
{
    /// <inheritdoc />
    public HipPluginManifest Manifest { get; } = new(
        Id: "sample",
        Version: "0.1.0",
        Capabilities: ["endpoint.sample.ping"],
        Description: "Sample plugin proving dynamic plugin registration.");

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        // No service registrations required for the sample plugin.
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        endpoints.MapGet("/api/plugins/sample/ping", () => Results.Ok(new
            {
                plugin = Manifest.Id,
                version = Manifest.Version,
                status = "ok",
                environment = environment.EnvironmentName
            }))
            .WithName("SamplePluginPing")
            .WithTags("Plugins");
    }
}
