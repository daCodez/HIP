using HIP.Security.Application.Abstractions.Audit;
using HIP.Security.Application.Abstractions.Generation;
using HIP.Security.Application.Abstractions.Mappings;
using HIP.Security.Application.Abstractions.Repositories;
using HIP.Security.Infrastructure.Generation;
using HIP.Security.Infrastructure.Mappings;
using HIP.Security.Infrastructure.Repositories;
using HIP.Security.PolicyEngine.DependencyInjection;
using HIP.Security.Simulator.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Security.Infrastructure.DependencyInjection;

public static class SecurityInfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddHipSecurityInfrastructure(this IServiceCollection services)
    {
        services.AddSingleton<IThreatRepository, InMemoryThreatRepository>();
        services.AddSingleton<IScenarioRepository, InMemoryScenarioRepository>();
        services.AddSingleton<IPolicyRepository, InMemoryPolicyRepository>();
        services.AddSingleton<IPolicyApprovalRepository, InMemoryPolicyApprovalRepository>();
        services.AddSingleton<IPolicyAuditRecorder, InMemoryPolicyAuditRecorder>();
        services.AddSingleton<IPolicySuggestionGenerator, StaticPolicySuggestionGenerator>();
        services.AddSingleton<IScenarioSuggestionGenerator, StaticScenarioSuggestionGenerator>();
        services.AddSingleton<ITelemetrySuggestionGenerator, StaticTelemetrySuggestionGenerator>();
        services.AddSingleton<IProtocolSecurityOutcomeMapper, ProtocolSecurityOutcomeMapper>();

        // Composition root for execution adapters.
        services.AddHipSecurityPolicyEngine();
        services.AddHipSecuritySimulator();

        return services;
    }
}
