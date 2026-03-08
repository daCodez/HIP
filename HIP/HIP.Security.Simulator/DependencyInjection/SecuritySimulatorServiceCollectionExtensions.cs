using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.Simulator.Execution;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Security.Simulator.DependencyInjection;

public static class SecuritySimulatorServiceCollectionExtensions
{
    public static IServiceCollection AddHipSecuritySimulator(this IServiceCollection services)
    {
        services.AddSingleton<ICampaignRunner, StubCampaignRunner>();
        services.AddSingleton<IReplayService, ReplayService>();
        return services;
    }
}
