using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.Plugins.Abstractions.Contracts;

/// <summary>
/// Tracks and applies registered HIP plugins.
/// </summary>
public interface IHipPluginRegistry
{
    /// <summary>
    /// Read-only snapshot of known plugin manifests.
    /// </summary>
    IReadOnlyList<HipPluginManifest> Manifests { get; }

    /// <summary>
    /// Registers a plugin instance.
    /// </summary>
    void Register(IHipPlugin plugin);

    /// <summary>
    /// Applies ConfigureServices for all registered plugins.
    /// </summary>
    void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment);

    /// <summary>
    /// Applies endpoint mapping for all registered plugins.
    /// </summary>
    void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment);
}
