using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.Plugins.Abstractions.Contracts;

/// <summary>
/// Represents a plugin that can register services and optional endpoints in HIP.
/// </summary>
public interface IHipPlugin
{
    /// <summary>
    /// Plugin metadata and capability declaration.
    /// </summary>
    HipPluginManifest Manifest { get; }

    /// <summary>
    /// Registers plugin services during application startup.
    /// </summary>
    void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment);

    /// <summary>
    /// Maps plugin endpoints after the application is built.
    /// </summary>
    void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment);
}
