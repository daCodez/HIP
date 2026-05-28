using FluentValidation;
using HIP.Application.PublicLookup;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.Scoring;
using HIP.Application.Simulation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddHipApplication(this IServiceCollection services)
    {
        var assembly = typeof(DependencyInjection).Assembly;

        services.AddMediatR(configuration => configuration.RegisterServicesFromAssembly(assembly));
        services.AddValidatorsFromAssembly(assembly);
        services.AddSingleton<IAiRiskAnalysisService, NoOpAiRiskAnalysisService>();
        services.AddSingleton<IRuleMatchingEngine, RuleMatchingEngine>();
        services.AddSingleton<IRuleActionApplier, RuleActionApplier>();
        services.AddSingleton<IRuleSimulationService, RuleSimulationService>();
        services.AddSingleton<IPublicDomainLookupService, PublicDomainLookupService>();
        services.AddSingleton<ITrustBadgeService, TrustBadgeService>();
        services.AddSingleton<ISafetyRoutingService, SafetyRoutingService>();

        return services;
    }
}
