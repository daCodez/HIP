using FluentValidation;
using HIP.Application.Ai;
using HIP.Application.Browser;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Identity;
using HIP.Application.Platforms;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.Scoring;
using HIP.Application.Security;
using HIP.Application.SecondLife;
using HIP.Application.SelfHealing;
using HIP.Application.Scans;
using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Application;

/// <summary>
/// Registers HIP application-layer services, validators, repositories, and security helpers.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds HIP application services without binding infrastructure-specific storage or secret configuration.
    /// Runtime hosts must also call HIP.Infrastructure's AddHipInfrastructure so live data comes from configured durable storage.
    /// In-memory repositories are intentionally kept out of this registration path and should be instantiated directly by tests.
    /// </summary>
    /// <param name="services">Service collection used by the host.</param>
    /// <returns>The same service collection for fluent registration.</returns>
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
        services.AddScoped<IRuleJsonService, RuleJsonService>();
        services.AddScoped<IAdminRuleService, AdminRuleService>();
        services.AddScoped<IPublicDomainLookupService, PublicDomainLookupService>();
        services.AddScoped<ITrustBadgeService, TrustBadgeService>();
        services.AddScoped<ISafetyRoutingService, SafetyRoutingService>();
        services.AddSingleton<IPatternDetectionService, PatternDetectionService>();
        services.AddSingleton<IRuleRollbackService, RuleRollbackService>();
        services.AddSingleton<IRuleCandidateGenerator, RuleCandidateGenerator>();
        services.AddSingleton<ISelfHealingAnalysisService, SelfHealingAnalysisService>();
        services.AddScoped<ISelfHealingPatternDetectionService, SelfHealingPatternDetectionService>();
        services.AddScoped<IConsumerPortalService, ConsumerPortalService>();
        services.AddScoped<IAdminDashboardService, AdminDashboardService>();
        services.AddScoped<IPlatformConnectionService, PlatformConnectionService>();
        services.AddScoped<IAuditLogService, AuditLogService>();
        services.AddScoped<IReviewQueueService, ReviewQueueService>();
        services.AddScoped<IAppealService, AppealService>();
        services.AddScoped<IReputationOverrideService, ReputationOverrideService>();
        services.AddScoped<IReputationService, ReputationService>();
        services.AddScoped<IWeightedFeedbackAggregationService, WeightedFeedbackAggregationService>();
        services.AddScoped<IRiskFindingIngestionService, RiskFindingIngestionService>();
        services.TryAddSingleton(new PrivacyHashingOptions());
        services.TryAddSingleton<IPrivacyStoragePolicy, DefaultPrivacyStoragePolicy>();
        services.TryAddSingleton<IProviderSubmissionPolicy, DefaultProviderSubmissionPolicy>();
        services.TryAddSingleton<IFeedbackWeightingPolicy, DefaultFeedbackWeightingPolicy>();
        services.AddSingleton<IPrivacyHashingService, Sha256PrivacyHashingService>();
        services.AddSingleton<IDuplicateSubmissionGuard, InMemoryDuplicateSubmissionGuard>();
        services.AddSingleton<ISubmissionRateLimiter, DevelopmentSubmissionRateLimiter>();
        services.AddScoped<IOutboxEventWriter, OutboxEventWriter>();
        services.AddSingleton<IReportRetentionPolicyService, ReportRetentionPolicyService>();
        services.AddSingleton<IPrivacySafeReportService, PrivacySafeReportService>();
        services.AddSingleton<IHipCryptoProvider, DevelopmentHipCryptoProvider>();
        services.AddScoped<IHipIdentityService, HipIdentityService>();
        services.AddScoped<IHipSignatureService, HipSignatureService>();
        services.AddScoped<IWebsiteIdentityService, WebsiteIdentityService>();
        services.TryAddSingleton<IDnsTxtRecordResolver, NoOpDnsTxtRecordResolver>();
        services.AddSingleton<IDomainVerificationService, DnsDomainVerificationService>();
        services.AddSingleton<ISetupCodeLicenseService, InMemorySetupCodeLicenseService>();
        services.AddScoped<ISecondLifeHudService, SecondLifeHudService>();
        services.AddScoped<ISecondLifeHudSimulationService, SecondLifeHudSimulationService>();
        services.AddScoped<IBrowserPluginService, BrowserPluginService>();
        services.AddScoped<IBrowserScanResultService, BrowserScanResultService>();
        services.AddScoped<IBrowserScanResultWriteService>(provider => (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IBrowserScanResultQueryService>(provider => (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IAdminScanDetailService, AdminScanDetailService>();
        services.AddScoped<ISiteSafetyScanner, SiteSafetyScanner>();
        services.AddScoped<ISiteSafetyScanResultStorageService, SiteSafetyScanResultStorageService>();
        services.AddScoped<IValidator<SiteSafetyScanRequest>, SiteSafetyScanValidator>();
        services.AddSingleton<IValidator<AdminSiteSafetyRule>, AdminSiteSafetyRuleValidator>();
        services.AddScoped<AdminSiteSafetyRuleService>();
        services.AddScoped<IAdminReviewQueueService, AdminReviewQueueService>();
        services.AddSingleton<IValidator<AdminReviewQueueItem>, AdminReviewQueueItemValidator>();
        services.AddSingleton(new SiteSafetyRuleOptions());
        services.AddSingleton(_ => new HttpClient());
        services.AddSingleton<IExternalSiteEvidenceCache, InMemoryExternalSiteEvidenceCache>();
        services.AddSingleton(new ExternalSiteEvidenceOptions());
        services.AddSingleton<IExternalSiteEvidenceSettingsStore, InMemoryExternalSiteEvidenceSettingsStore>();
        services.AddSingleton<IExternalProviderResiliencePolicy, InMemoryExternalProviderResiliencePolicy>();
        services.AddScoped<ISiteSafetyEvidenceProvider, BrowserObservedSignalProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, WeightedFeedbackSiteSafetyEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, AdminReviewEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, SslLabsSiteEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, GoogleWebRiskSiteEvidenceProvider>();
        services.AddScoped<ISiteSafetyEvidenceProvider, VirusTotalSiteEvidenceProvider>();

        return services;
    }
}
