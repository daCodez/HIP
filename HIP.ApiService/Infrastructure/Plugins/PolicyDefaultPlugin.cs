using HIP.ApiService.Application.Abstractions;
using HIP.Plugins.Abstractions.Contracts;
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
        Description: "Registers the default policy evaluator for allow/review/block decisions.");

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddScoped<IJarvisPolicyEvaluator, DefaultJarvisPolicyEvaluator>();
    }

    /// <inheritdoc />
    public void MapEndpoints(IEndpointRouteBuilder endpoints, IConfiguration configuration, IHostEnvironment environment)
    {
    }
}
