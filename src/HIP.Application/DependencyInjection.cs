using FluentValidation;
using HIP.Application.Browser;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.Scoring;
using HIP.Application.SecondLife;
using HIP.Application.SelfHealing;
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
        services.AddSingleton<IRuleEvaluationService, RuleEvaluationService>();
        services.AddSingleton<IRuleSimulationService, RuleSimulationService>();
        services.AddSingleton<IRuleSimulationResultRepository, InMemoryRuleSimulationResultRepository>();
        services.AddScoped<IRuleJsonService, RuleJsonService>();
        services.AddScoped<IRuleRepository, InMemoryRuleRepository>();
        services.AddScoped<IAdminRuleService, AdminRuleService>();
        services.AddScoped<IPublicDomainLookupService, PublicDomainLookupService>();
        services.AddScoped<ITrustBadgeService, TrustBadgeService>();
        services.AddScoped<ISafetyRoutingService, SafetyRoutingService>();
        services.AddSingleton<IPatternDetectionService, PatternDetectionService>();
        services.AddSingleton<IRuleRollbackService, RuleRollbackService>();
        services.AddSingleton<IRuleCandidateGenerator, RuleCandidateGenerator>();
        services.AddSingleton<ISelfHealingAnalysisService, SelfHealingAnalysisService>();
        services.AddScoped<IConsumerPortalService, ConsumerPortalService>();
        services.AddScoped<IAdminDashboardService, AdminDashboardService>();
        services.AddScoped<IAuditLogService, AuditLogService>();
        services.AddScoped<IReviewQueueService, ReviewQueueService>();
        services.AddScoped<IAppealService, AppealService>();
        services.AddScoped<IReputationOverrideService, ReputationOverrideService>();
        services.AddScoped<IReputationEventRepository, InMemoryReputationEventRepository>();
        services.AddScoped<IReputationProfileRepository, InMemoryReputationProfileRepository>();
        services.AddScoped<IReputationService, ReputationService>();
        services.AddScoped<IRiskFindingReportRepository, InMemoryRiskFindingReportRepository>();
        services.AddScoped<IRiskFindingIngestionService, RiskFindingIngestionService>();
        services.AddSingleton<IHipCryptoProvider, DevelopmentHipCryptoProvider>();
        services.AddScoped<IHipIdentityRepository, InMemoryHipIdentityRepository>();
        services.AddScoped<IHipIdentityService, HipIdentityService>();
        services.AddScoped<IDomainVerificationService, InMemoryDomainVerificationService>();
        services.AddScoped<ISecondLifeHudService, SecondLifeHudService>();
        services.AddScoped<IBrowserPluginService, BrowserPluginService>();

        return services;
    }
}
