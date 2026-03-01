using Microsoft.Extensions.DependencyInjection;

namespace HIP.Sdk;

/// <summary>
/// Dependency injection helpers for registering the HIP SDK client.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IHipSdkClient"/> as an <see cref="HttpClient"/>-backed service.
    /// </summary>
    /// <param name="services">Target service collection.</param>
    /// <param name="configure">
    /// Optional options callback used to override defaults such as API base URL.
    /// </param>
    /// <returns>The same service collection for fluent chaining.</returns>
    public static IServiceCollection AddHipSdkClient(this IServiceCollection services, Action<HipSdkOptions>? configure = null)
    {
        var options = new HipSdkOptions();
        configure?.Invoke(options);

        services.AddHttpClient<IHipSdkClient, HipSdkClient>(client =>
        {
            // All SDK calls are relative paths, so base address must be set here.
            client.BaseAddress = new Uri(options.BaseUrl);
        });

        services.AddHttpClient<IHipSdkAdminClient, HipSdkAdminClient>(client =>
        {
            client.BaseAddress = new Uri(options.BaseUrl);
        });

        return services;
    }
}
