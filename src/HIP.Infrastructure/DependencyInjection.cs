using HIP.Application.Browser;
using HIP.Application.Identity;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.SelfHealing;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Infrastructure;

/// <summary>
/// Registers HIP infrastructure services such as EF Core repositories, record encryption, and secure hashing options.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds HIP infrastructure services and binds environment-aware security options.
    /// </summary>
    /// <param name="services">Service collection used by the host.</param>
    /// <param name="configuration">Configuration containing connection strings and HIP security keys.</param>
    /// <param name="isLocalDevelopment">Whether shared development keys and safe create behavior may be used.</param>
    /// <returns>The same service collection for fluent registration.</returns>
    public static IServiceCollection AddHipInfrastructure(this IServiceCollection services, IConfiguration configuration, bool isLocalDevelopment = true)
    {
        var connectionString = configuration.GetConnectionString("HipDatabase") ?? "Data Source=hip-dev.db";

        services.AddDbContext<HipDbContext>(options => options.UseSqlite(connectionString));
        services.AddSingleton(BindRecordEncryptionOptions(configuration, isLocalDevelopment));
        services.AddSingleton(BindPrivacyHashingOptions(configuration, isLocalDevelopment));
        services.AddSingleton<IHipRecordEncryptor, DevelopmentHipRecordEncryptor>();
        services.AddScoped<HipRecordStore>();

        services.AddScoped<IHipIdentityRepository, EfHipIdentityRepository>();
        services.AddScoped<IReputationProfileRepository, EfReputationProfileRepository>();
        services.AddScoped<IReputationEventRepository, EfReputationEventRepository>();
        services.AddScoped<IRuleRepository, EfRuleRepository>();
        services.AddScoped<IRiskFindingReportRepository, EfRiskFindingReportRepository>();
        services.AddScoped<IReviewQueueRepository, EfReviewQueueRepository>();
        services.AddScoped<IAuditLogRepository, EfAuditLogRepository>();
        services.AddScoped<IAppealRepository, EfAppealRepository>();
        services.AddScoped<IReputationOverrideRequestRepository, EfReputationOverrideRequestRepository>();
        services.AddScoped<IRuleSimulationResultRepository, EfRuleSimulationResultRepository>();
        services.AddScoped<IGeneratedRuleCandidateRepository, EfGeneratedRuleCandidateRepository>();
        services.AddScoped<IBrowserScanResultRepository, EfBrowserScanResultRepository>();
        services.AddScoped<IAdminSiteSafetyRuleRepository, EfAdminSiteSafetyRuleRepository>();
        services.AddScoped<IWeightedFeedbackRepository, EfWeightedFeedbackRepository>();
        services.AddScoped<IAdminReviewQueueRepository, EfAdminReviewQueueRepository>();

        return services;
    }

    /// <summary>
    /// Binds record encryption settings and disables default keys outside local Development.
    /// </summary>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="isLocalDevelopment">Whether the host is a local Development process.</param>
    /// <returns>Record encryption options.</returns>
    private static HipRecordEncryptionOptions BindRecordEncryptionOptions(IConfiguration configuration, bool isLocalDevelopment) =>
        new(
            configuration["HipSecurity:RecordEncryptionKey"] ?? DevelopmentHipRecordEncryptor.DevelopmentOnlyKey,
            AllowDevelopmentKey: isLocalDevelopment);

    /// <summary>
    /// Binds privacy HMAC settings and disables default keys outside local Development.
    /// </summary>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="isLocalDevelopment">Whether the host is a local Development process.</param>
    /// <returns>Privacy hashing options.</returns>
    private static PrivacyHashingOptions BindPrivacyHashingOptions(IConfiguration configuration, bool isLocalDevelopment) =>
        new(
            configuration["HipSecurity:PrivacyHashingKey"] ?? Sha256PrivacyHashingService.DevelopmentOnlyKey,
            AllowDevelopmentKey: isLocalDevelopment);
}
