using FluentValidation;
using HIP.Application.Ai;
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
using HIP.Application.Scans;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
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
        services.AddSingleton<IValidator<ReviewItem>, ReviewItemValidator>();
        services.AddSingleton<IValidator<AppealRequest>, AppealRequestValidator>();
        services.AddSingleton<IValidator<ReputationOverrideRequest>, ReputationOverrideRequestValidator>();
        services.AddSingleton<IValidator<PrivacySafeReport>, PrivacySafeReportValidator>();
        services.AddSingleton<IAiRiskAnalysisService, NoOpAiRiskAnalysisService>();
        services.AddSingleton<IHipAiRiskAnalyzer, DevelopmentHipAiRiskAnalyzer>();
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
        services.AddScoped<ISelfHealingPatternDetectionService, SelfHealingPatternDetectionService>();
        services.AddScoped<IGeneratedRuleCandidateRepository, InMemoryGeneratedRuleCandidateRepository>();
        services.AddScoped<IConsumerPortalService, ConsumerPortalService>();
        services.AddScoped<IAdminDashboardService, AdminDashboardService>();
        services.AddSingleton<IAuditLogService, AuditLogService>();
        services.AddSingleton<IReviewQueueService, ReviewQueueService>();
        services.AddSingleton<IAppealService, AppealService>();
        services.AddSingleton<IReputationOverrideService, ReputationOverrideService>();
        services.AddScoped<IReputationEventRepository, InMemoryReputationEventRepository>();
        services.AddScoped<IReputationProfileRepository, InMemoryReputationProfileRepository>();
        services.AddScoped<IReputationService, ReputationService>();
        services.AddScoped<IWeightedFeedbackRepository, InMemoryWeightedFeedbackRepository>();
        services.AddScoped<IWeightedFeedbackAggregationService, WeightedFeedbackAggregationService>();
        services.AddScoped<IRiskFindingReportRepository, InMemoryRiskFindingReportRepository>();
        services.AddScoped<IRiskFindingIngestionService, RiskFindingIngestionService>();
        services.AddSingleton<IPrivacyHashingService, Sha256PrivacyHashingService>();
        services.AddSingleton<IReportRetentionPolicyService, ReportRetentionPolicyService>();
        services.AddSingleton<IPrivacySafeReportService, PrivacySafeReportService>();
        services.AddSingleton<IHipCryptoProvider, DevelopmentHipCryptoProvider>();
        services.AddScoped<IHipIdentityRepository, InMemoryHipIdentityRepository>();
        services.AddScoped<IHipIdentityService, HipIdentityService>();
        services.AddScoped<IHipSignatureService, HipSignatureService>();
        services.AddScoped<IWebsiteIdentityService, WebsiteIdentityService>();
        services.AddSingleton<IDomainVerificationService, InMemoryDomainVerificationService>();
        services.AddSingleton<ISetupCodeLicenseService, InMemorySetupCodeLicenseService>();
        services.AddScoped<ISecondLifeHudService, SecondLifeHudService>();
        services.AddScoped<ISecondLifeHudSimulationService, SecondLifeHudSimulationService>();
        services.AddScoped<IBrowserPluginService, BrowserPluginService>();
        services.AddScoped<IBrowserScanResultRepository, InMemoryBrowserScanResultRepository>();
        services.AddScoped<IBrowserScanResultService, BrowserScanResultService>();
        services.AddScoped<IAdminScanDetailService, AdminScanDetailService>();
        services.AddScoped<ISiteSafetyScanner, SiteSafetyScanner>();
        services.AddScoped<IValidator<SiteSafetyScanRequest>, SiteSafetyScanValidator>();
        services.AddSingleton<IValidator<AdminSiteSafetyRule>, AdminSiteSafetyRuleValidator>();
        services.AddScoped<IAdminSiteSafetyRuleRepository, InMemoryAdminSiteSafetyRuleRepository>();
        services.AddScoped<AdminSiteSafetyRuleService>();
        services.AddScoped<IAdminReviewQueueRepository, InMemoryAdminReviewQueueRepository>();
        services.AddScoped<IAdminReviewQueueService, AdminReviewQueueService>();
        services.AddSingleton<IValidator<AdminReviewQueueItem>, AdminReviewQueueItemValidator>();
        services.AddSingleton(new SiteSafetyRuleOptions());
        services.AddSingleton(_ => new HttpClient());
        services.AddSingleton<IExternalSiteEvidenceCache, InMemoryExternalSiteEvidenceCache>();
        services.AddSingleton(new ExternalSiteEvidenceOptions());
        services.AddScoped<ISiteSafetyEvidenceProvider, BrowserObservedSignalProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, WeightedFeedbackSiteSafetyEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, AdminReviewEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, SslLabsSiteEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, GoogleWebRiskSiteEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, VirusTotalSiteEvidenceProvider>();

        return services;
    }
}
