using HIP.Security.Application.Abstractions.Execution;
using HIP.Security.PolicyEngine.Execution;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Security.PolicyEngine.DependencyInjection;

public static class SecurityPolicyEngineServiceCollectionExtensions
{
    public static IServiceCollection AddHipSecurityPolicyEngine(this IServiceCollection services)
    {
        services.AddSingleton<IMutationEngine, PassThroughMutationEngine>();
        services.AddSingleton<ICoverageEvaluator, BasicCoverageEvaluator>();
        return services;
    }
}
