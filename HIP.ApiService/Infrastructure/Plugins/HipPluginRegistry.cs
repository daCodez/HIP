using HIP.Plugins.Abstractions.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// In-process plugin registry for HIP runtime composition.
/// </summary>
public sealed class HipPluginRegistry : IHipPluginRegistry
{
    private readonly List<IHipPlugin> _plugins = [];

    /// <inheritdoc />
    public IReadOnlyList<HipPluginManifest> Manifests => _plugins.Select(x => x.Manifest).ToArray();

    /// <inheritdoc />
    public void Register(IHipPlugin plugin)
    {
        ArgumentNullException.ThrowIfNull(plugin);

        if (string.IsNullOrWhiteSpace(plugin.Manifest.Id))
        {
            throw new InvalidOperationException("Plugin manifest id is required.");
        }

        if (_plugins.Any(x => string.Equals(x.Manifest.Id, plugin.Manifest.Id, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Plugin already registered: {plugin.Manifest.Id}");
        }

        _plugins.Add(plugin);
    }

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        foreach (var plugin in _plugins)
        {
            plugin.ConfigureServices(services, configuration, environment);
        }
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
        foreach (var plugin in _plugins)
        {
            plugin.MapEndpoints(endpoints, configuration, environment);
        }
    }
}
