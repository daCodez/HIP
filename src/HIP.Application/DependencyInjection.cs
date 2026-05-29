using FluentValidation;
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
        services.AddSingleton<IRuleSimulationService, RuleSimulationService>();
        services.AddSingleton<IRuleJsonService, RuleJsonService>();
        services.AddSingleton<IRuleRepository, InMemoryRuleRepository>();
        services.AddSingleton<IAdminRuleService, AdminRuleService>();
        services.AddSingleton<IPublicDomainLookupService, PublicDomainLookupService>();
        services.AddSingleton<ITrustBadgeService, TrustBadgeService>();
        services.AddSingleton<ISafetyRoutingService, SafetyRoutingService>();
        services.AddSingleton<IPatternDetectionService, PatternDetectionService>();
        services.AddSingleton<IRuleRollbackService, RuleRollbackService>();
        services.AddSingleton<IRuleCandidateGenerator, RuleCandidateGenerator>();
        services.AddSingleton<ISelfHealingAnalysisService, SelfHealingAnalysisService>();
        services.AddSingleton<IAuditLogService, AuditLogService>();
        services.AddSingleton<IReviewQueueService, ReviewQueueService>();
        services.AddSingleton<IAppealService, AppealService>();
        services.AddSingleton<IReputationOverrideService, ReputationOverrideService>();
        services.AddSingleton<IReputationEventRepository, InMemoryReputationEventRepository>();
        services.AddSingleton<IReputationProfileRepository, InMemoryReputationProfileRepository>();
        services.AddSingleton<IReputationService, ReputationService>();
        services.AddSingleton<IRiskFindingReportRepository, InMemoryRiskFindingReportRepository>();
        services.AddSingleton<IRiskFindingIngestionService, RiskFindingIngestionService>();
        services.AddSingleton<IHipCryptoProvider, DevelopmentHipCryptoProvider>();
        services.AddSingleton<IHipIdentityRepository, InMemoryHipIdentityRepository>();
        services.AddSingleton<IHipIdentityService, HipIdentityService>();
        services.AddSingleton<IDomainVerificationService, InMemoryDomainVerificationService>();
        services.AddSingleton<ISecondLifeHudService, SecondLifeHudService>();

        return services;
    }
}
