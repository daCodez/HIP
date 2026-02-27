using Microsoft.Extensions.DependencyInjection;

namespace HIP.Sdk;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddHipSdkClient(this IServiceCollection services, Action<HipSdkOptions>? configure = null)
    {
        var options = new HipSdkOptions();
        configure?.Invoke(options);

        services.AddHttpClient<IHipSdkClient, HipSdkClient>(client =>
        {
            client.BaseAddress = new Uri(options.BaseUrl);
        });

        return services;
    }
}
