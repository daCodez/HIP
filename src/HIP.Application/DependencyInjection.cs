using FluentValidation;
using HIP.Application.Ai;
using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.Consumer;
using HIP.Application.Dashboard;
using HIP.Application.Devices;
using HIP.Application.Identity;
using HIP.Application.Explanations;
using HIP.Application.Platforms;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Safety;
using HIP.Application.Scoring;
using HIP.Application.Security;
using HIP.Application.SecondLife;
using HIP.Application.ServiceClients;
using HIP.Application.SelfHealing;
using HIP.Application.Scans;
using HIP.Application.Scalability;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Domain.Reporting;
using HIP.Domain.Certificates;
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
    /// <param name="allowDevelopmentCryptoProvider">
    /// True only for an explicit Development or test host. The secure default excludes placeholder crypto.
    /// </param>
    /// <returns>The same service collection for fluent registration.</returns>
    public static IServiceCollection AddHipApplication(
        this IServiceCollection services,
        bool allowDevelopmentCryptoProvider = false)
    {
        var assembly = typeof(DependencyInjection).Assembly;
        services.AddScoped<IDomainCertificateEnrollmentService, DomainCertificateEnrollmentService>();
        services.AddScoped<IDomainCertificateLifecycleService, DomainCertificateLifecycleService>();

        services.AddMediatR(configuration => configuration.RegisterServicesFromAssembly(assembly));
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(DomainCertificatePolicy.V1);
        var developmentSigningMaterial = allowDevelopmentCryptoProvider
            ? DevelopmentManagedTrustReceiptSigningMaterial.Create()
            : null;
        if (developmentSigningMaterial is null)
        {
            services.TryAddSingleton(new DomainCertificateSigningAuthorityPolicy([]));
        }
        else
        {
            services.AddSingleton(developmentSigningMaterial);
            services.AddSingleton(new DomainCertificateSigningAuthorityPolicy(
            [
                new DomainCertificateAuthorizedSigner(
                    DevelopmentManagedTrustReceiptSigningMaterial.IssuerId,
                    developmentSigningMaterial.KeyId)
            ]));
        }
        services.AddSingleton<DomainRegistrationNormalizer>();
        services.AddSingleton<IDomainCertificatePolicyEvaluator, DomainCertificatePolicyEvaluator>();
        services.AddScoped<IDomainCertificateSigningService, DomainCertificateSigningService>();
        services.AddScoped<IDomainCertificateIssuanceService, DomainCertificateIssuanceService>();
        services.AddScoped<IPublicDomainCertificateService, PublicDomainCertificateService>();
        services.AddValidatorsFromAssembly(assembly);
        services.AddSingleton<IValidator<ReviewItem>, ReviewItemValidator>();
        services.AddSingleton<IValidator<AppealRequest>, AppealRequestValidator>();
        services.AddSingleton<IValidator<ReputationOverrideRequest>, ReputationOverrideRequestValidator>();
        services.AddSingleton<IValidator<PrivacySafeReport>, PrivacySafeReportValidator>();
        services.AddSingleton<IAiRiskAnalysisService, NoOpAiRiskAnalysisService>();
        services.TryAddSingleton<IHipScoreConstraintPolicy, HipMandatoryScoreConstraintPolicy>();
        services.TryAddSingleton<IHipScoringPipeline, HipScoringPipeline>();
        services.AddSingleton<ICanonicalJsonService, Rfc8785CanonicalJsonService>();
        services.AddSingleton<IHipAiRiskAnalyzer, DevelopmentHipAiRiskAnalyzer>();
        services.AddSingleton<IRuleConditionEvaluator, RuleConditionEvaluator>();
        services.AddSingleton<IRuleMatchingEngine, RuleMatchingEngine>();
        services.AddSingleton<IRuleActionApplier, RuleActionApplier>();
        services.AddSingleton<IRuleEvaluationService, RuleEvaluationService>();
        services.AddSingleton<IRuleSimulationService, RuleSimulationService>();
        services.AddScoped<IRuleJsonService, RuleJsonService>();
        services.AddScoped<IAdminRuleService, AdminRuleService>();
        services.AddScoped<RuleApprovalWorkflowService>();
        services.AddScoped<RuleDeploymentService>();
        services.AddScoped<AiRuleDraftService>();
        services.AddScoped<IPublicDomainLookupService, PublicDomainLookupService>();
        services.AddSingleton<ITrustExplanationProvider, DisabledTrustExplanationProvider>();
        services.AddSingleton<ITrustExplanationAssistant, TrustExplanationAssistant>();
        services.AddScoped<ITrustBadgeService, TrustBadgeService>();
        services.AddScoped<ISafetyRoutingService, SafetyRoutingService>();
        services.TryAddSingleton<ISafetyDecisionRepository, InMemorySafetyDecisionRepository>();
        services.AddScoped<ISafetyDecisionService, SafetyDecisionService>();
        services.AddSingleton<IPatternDetectionService, PatternDetectionService>();
        services.AddSingleton<IRuleRollbackService, RuleRollbackService>();
        services.AddSingleton<IRuleCandidateGenerator, RuleCandidateGenerator>();
        services.AddSingleton<ISelfHealingAnalysisService, SelfHealingAnalysisService>();
        services.AddScoped<ISelfHealingPatternDetectionService, SelfHealingPatternDetectionService>();
        services.AddScoped<IConsumerPortalService, ConsumerPortalService>();
        services.TryAddSingleton<IConsumerSettingsRepository, InMemoryConsumerSettingsRepository>();
        services.TryAddSingleton(DeviceRegistrationPolicy.Default);
        services.TryAddSingleton<Es256DeviceProofVerifier>();
        services.TryAddSingleton<DeviceRegistrationKeyDerivation>();
        services.AddScoped<IDeviceRegistrationService, DeviceRegistrationService>();
        services.AddScoped<IDeviceRequestProofService, DeviceRequestProofService>();
        services.TryAddSingleton<IServiceClientCredentialGenerator, CryptographicServiceClientCredentialGenerator>();
        services.TryAddSingleton<IServiceClientSecretProtector, Pbkdf2ServiceClientSecretProtector>();
        services.TryAddSingleton<ServiceClientOwnerScopeDerivation>();
        // HIP.Infrastructure replaces this safe fallback with the shared Redis-backed actor budget.
        services.TryAddSingleton<IServiceClientManagementMutationLimiter, UnavailableServiceClientManagementMutationLimiter>();
        services.AddScoped<ServiceClientLifecycleService>();
        services.AddScoped<IServiceClientLifecycleService, RateLimitedServiceClientLifecycleService>();
        services.AddScoped<IAdminDashboardService, AdminDashboardService>();
        services.AddScoped<IPlatformConnectionService, PlatformConnectionService>();
        services.AddScoped<IAuditLogService, AuditLogService>();
        services.AddScoped<IAuditExportService, AuditExportService>();
        services.AddScoped<IReviewQueueService, ReviewQueueService>();
        services.AddScoped<IAppealService, AppealService>();
        services.AddScoped<IReputationOverrideService, ReputationOverrideService>();
        services.AddSingleton<IReputationScoringPolicy, DefaultReputationScoringPolicy>();
        services.AddScoped<IReputationService, ReputationService>();
        services.AddScoped<IAdminSenderProfileService, AdminSenderProfileService>();
        services.AddScoped<IWeightedFeedbackAggregationService, WeightedFeedbackAggregationService>();
        services.AddScoped<IAdminFeedbackService, AdminFeedbackService>();
        services.AddScoped<IRiskFindingIngestionService, RiskFindingIngestionService>();
        services.AddScoped<IRiskFindingRetentionService, RiskFindingRetentionService>();
        services.TryAddSingleton(new PrivacyHashingOptions());
        services.TryAddSingleton<IPrivacyStoragePolicy, DefaultPrivacyStoragePolicy>();
        services.TryAddSingleton<IProviderSubmissionPolicy, DefaultProviderSubmissionPolicy>();
        services.TryAddSingleton<IFeedbackWeightingPolicy, DefaultFeedbackWeightingPolicy>();
        services.AddSingleton<IPrivacyHashingService, Sha256PrivacyHashingService>();
        services.AddSingleton<IHudDeviceCredentialService, HudDeviceCredentialService>();
        // Runtime duplicate detection is supplied by HIP.Infrastructure so public submissions are deduped through durable storage.
        services.AddSingleton<ISubmissionRateLimiter, DevelopmentSubmissionRateLimiter>();
        services.AddScoped<IOutboxEventWriter, OutboxEventWriter>();
        services.AddSingleton<IReportRetentionPolicyService, ReportRetentionPolicyService>();
        services.AddSingleton<IPrivacySafeReportService, PrivacySafeReportService>();
        services.AddSingleton<MlDsa65SignatureProvider>();
        services.AddSingleton<IHipSignatureProvider>(provider =>
            provider.GetRequiredService<MlDsa65SignatureProvider>());
        services.RemoveAll<DevelopmentHipCryptoProviderOptions>();
        services.AddSingleton(new DevelopmentHipCryptoProviderOptions(allowDevelopmentCryptoProvider));
        services.AddSingleton<DevelopmentHipCryptoProvider>();
        services.AddSingleton<IHipCryptoProvider>(provider =>
            provider.GetRequiredService<DevelopmentHipCryptoProvider>());
        if (allowDevelopmentCryptoProvider)
        {
            services.AddSingleton<IHipSignatureProvider>(provider =>
                provider.GetRequiredService<DevelopmentHipCryptoProvider>());
        }

        services.AddSingleton(allowDevelopmentCryptoProvider
            ? SignatureProviderRuntimePolicy.ForDevelopment(
                MlDsa65SignatureProvider.Algorithm,
                DevelopmentHipCryptoProvider.Algorithm)
            : SignatureProviderRuntimePolicy.ForProduction(MlDsa65SignatureProvider.Algorithm));
        services.AddSingleton<IHipSignatureProviderFactory, HipSignatureProviderFactory>();
        services.AddSingleton<IHipPublicKeyFingerprintService, HipPublicKeyFingerprintService>();
        services.AddScoped<IHipSignedDocumentVerifier, HipSignedDocumentVerifier>();
        services.AddScoped<IHipEnvelopeVerificationService, HipEnvelopeVerificationService>();
        services.TryAddSingleton(HipTrustReceiptPolicy.Default);
        if (developmentSigningMaterial is null)
        {
            services.TryAddSingleton(HipTrustReceiptIssuerPolicy.Default);
        }
        else
        {
            services.AddSingleton(new HipTrustReceiptIssuerPolicy(
            [
                new HipTrustReceiptAuthorizedSigner(
                    DevelopmentManagedTrustReceiptSigningMaterial.IssuerId,
                    developmentSigningMaterial.KeyId)
            ]));
        }
        services.TryAddSingleton(HipLiveBadgePolicy.Default);
        if (developmentSigningMaterial is null)
        {
            services.TryAddScoped<IManagedTrustReceiptSigner, UnavailableManagedTrustReceiptSigner>();
        }
        else
        {
            services.AddScoped<IManagedTrustReceiptSigner, DevelopmentManagedTrustReceiptSigner>();
        }
        services.AddScoped<IHipLiveBadgeSigningService, HipLiveBadgeSigningService>();
        services.AddScoped<IHipLiveBadgeVerificationService, HipLiveBadgeVerificationService>();
        services.AddScoped<IHipTrustReceiptAuthoritativeEvaluationService, HipTrustReceiptAuthoritativeEvaluationService>();
        services.AddScoped<IHipTrustReceiptEvidenceDigestService, HipTrustReceiptEvidenceDigestService>();
        services.AddScoped<IHipTrustReceiptVerificationService, HipTrustReceiptVerificationService>();
        services.AddScoped<IHipTrustReceiptIssuanceService, HipTrustReceiptIssuanceService>();
        services.TryAddSingleton(HipReplayProtectionPolicy.Default);
        services.AddScoped<IHipReplayProtectionService, HipReplayProtectionService>();
        services.AddScoped<IHipIdentityService, HipIdentityService>();
        services.AddScoped<IHipSignatureService, HipSignatureService>();
        services.AddScoped<ISigningKeyLifecycleService, SigningKeyLifecycleService>();
        services.AddScoped<IWebsiteIdentityService, WebsiteIdentityService>();
        services.AddScoped<IDomainVerificationLifecycleCoordinator, DomainVerificationLifecycleCoordinator>();
        services.TryAddSingleton<IDnsTxtRecordResolver, NoOpDnsTxtRecordResolver>();
        services.TryAddSingleton<IWellKnownHipDocumentFetcher, UnavailableWellKnownHipDocumentFetcher>();
        services.AddScoped<IWellKnownHipDocumentVerifier, WellKnownHipDocumentVerifier>();
        services.AddScoped<IDomainVerificationService, DnsDomainVerificationService>();
        // Runtime setup-code licenses are supplied by HIP.Infrastructure so HUD activation state survives restarts.
        services.AddScoped<ISecondLifeHudService, SecondLifeHudService>();
        services.AddScoped<ISecondLifeHudSimulationService, SecondLifeHudSimulationService>();
        services.AddScoped<IBrowserPluginService, BrowserPluginService>();
        services.AddScoped<IBrowserScanResultService, BrowserScanResultService>();
        services.AddScoped<IUntrustedBrowserScanResultSubmissionService>(provider =>
            (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IRegisteredDeviceBrowserScanResultSubmissionService>(provider =>
            (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IBrowserScanResultWriteService>(provider => (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IBrowserScanResultQueryService>(provider => (BrowserScanResultService)provider.GetRequiredService<IBrowserScanResultService>());
        services.AddScoped<IAdminScanDetailService, AdminScanDetailService>();
        services.AddScoped<ISiteSafetyScanner, SiteSafetyScanner>();
        services.AddScoped<IUntrustedSiteSafetyScanner>(provider =>
            (SiteSafetyScanner)provider.GetRequiredService<ISiteSafetyScanner>());
        services.AddScoped<ISandboxLinkScanService, SandboxLinkScanService>();
        // Sandbox scan queue persistence is supplied by HIP.Infrastructure so local and production behavior use durable state.
        services.AddSingleton(new SandboxLinkScanOptions());
        services.AddScoped<ExternalSiteEvidenceCollector>();
        services.AddScoped<IExternalSiteEvidenceCollector>(provider =>
            provider.GetRequiredService<ExternalSiteEvidenceCollector>());
        services.AddScoped<IExternalSiteEvidenceWorkCollector>(provider =>
            provider.GetRequiredService<ExternalSiteEvidenceCollector>());
        services.AddScoped<ExternalSiteEvidenceJobService>();
        services.AddScoped<ExternalSiteEvidenceJobProcessor>();
        services.AddSingleton(new ExternalSiteEvidenceJobOptions());
        services.AddScoped<ISiteSafetyScanResultStorageService, SiteSafetyScanResultStorageService>();
        services.AddScoped<IValidator<SiteSafetyScanRequest>, SiteSafetyScanValidator>();
        services.AddSingleton<IValidator<AdminSiteSafetyRule>, AdminSiteSafetyRuleValidator>();
        services.AddScoped<AdminSiteSafetyRuleService>();
        services.AddScoped<IAdminReviewQueueService, AdminReviewQueueService>();
        services.AddSingleton<IValidator<AdminReviewQueueItem>, AdminReviewQueueItemValidator>();
        services.AddSingleton(new SiteSafetyRuleOptions());
        services.AddSingleton(_ => new HttpClient());
        // Runtime provider cache/settings/resilience are supplied by HIP.Infrastructure so provider work is not process-local.
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
