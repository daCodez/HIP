using HIP.Security.Application.Abstractions.Policies;
using HIP.Security.Application.Policies.Internal;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Security.Application.DependencyInjection;

public static class SecurityApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddHipSecurityApplication(this IServiceCollection services)
    {
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(SecurityApplicationServiceCollectionExtensions).Assembly));
        services.AddSingleton<IPolicyLifecycleGuard, PolicyLifecycleGuard>();
        return services;
    }
}
