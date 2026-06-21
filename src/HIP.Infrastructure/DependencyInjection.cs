using HIP.Application.Browser;
using HIP.Application.Identity;
using HIP.Application.Platforms;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.SelfHealing;
using HIP.Application.SiteSafety;
using HIP.Application.Simulation;
using HIP.Infrastructure.Identity;
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
        var connectionString = configuration.GetConnectionString("HipDatabase")
            ?? throw new InvalidOperationException("HIP requires ConnectionStrings:HipDatabase. Run HIP.AppHost to use Aspire-managed PostgreSQL, or set ConnectionStrings__HipDatabase explicitly for direct project runs.");
        var databaseProvider = configuration["HipInfrastructure:DatabaseProvider"];

        services.AddDbContext<HipDbContext>(options => ConfigureDatabaseProvider(options, connectionString, databaseProvider));
        services.AddSingleton(BindRecordEncryptionOptions(configuration, isLocalDevelopment));
        services.AddSingleton(BindPrivacyHashingOptions(configuration, isLocalDevelopment));
        services.AddSingleton<IHipRecordEncryptor, DevelopmentHipRecordEncryptor>();
        services.AddScoped<HipRecordStore>();
        services.AddOptions<DnsVerificationOptions>()
            .Bind(configuration.GetSection(DnsVerificationOptions.SectionName))
            .Validate(ValidateDnsVerificationOptions, "DNS verification options must use a valid port and timeout.")
            .ValidateOnStart();
        services.AddSingleton<IDnsTxtRecordResolver, DnsClientTxtRecordResolver>();

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
        services.AddScoped<IOutboxEventRepository, EfOutboxEventRepository>();
        services.AddScoped<IInboxEventRepository, EfInboxEventRepository>();
        services.AddScoped<IScanResultCache, EfScanResultCache>();
        services.AddScoped<IScanIngestionQueue, EfScanIngestionQueue>();
        services.AddScoped<IScanResultDedupeService, EfScanResultDedupeService>();
        services.AddScoped<IDashboardScanAggregateStore, EfDashboardScanAggregateStore>();
        services.AddScoped<IPlatformConnectionRepository, EfPlatformConnectionRepository>();

        return services;
    }

    /// <summary>
    /// Selects the EF Core provider from configuration. HIP runtime persistence is PostgreSQL-only so the
    /// deployed app does not carry the vulnerable SQLite native dependency reported by package audit tooling.
    /// </summary>
    /// <param name="options">EF Core options builder being configured for HIP persistence.</param>
    /// <param name="connectionString">Database connection string supplied by configuration or Aspire service discovery.</param>
    /// <param name="databaseProvider">Optional provider name, such as PostgreSQL or SQLite.</param>
    private static void ConfigureDatabaseProvider(DbContextOptionsBuilder options, string connectionString, string? databaseProvider)
    {
        if (!ShouldUsePostgreSql(connectionString, databaseProvider))
        {
            throw new InvalidOperationException(
                "HIP runtime persistence requires PostgreSQL. Run HIP.AppHost to use Aspire-managed PostgreSQL, or set ConnectionStrings__HipDatabase to a PostgreSQL connection string. SQLite is supported only by tests that configure DbContext directly.");
        }

        options.UseNpgsql(connectionString);
    }

    /// <summary>
    /// Detects PostgreSQL configuration without treating every arbitrary connection string as safe for Npgsql.
    /// </summary>
    /// <param name="connectionString">Configured database connection string.</param>
    /// <param name="databaseProvider">Optional explicit provider name from configuration.</param>
    /// <returns>True when HIP should use the PostgreSQL EF Core provider.</returns>
    private static bool ShouldUsePostgreSql(string connectionString, string? databaseProvider) =>
        string.Equals(databaseProvider, "PostgreSQL", StringComparison.OrdinalIgnoreCase)
        || string.Equals(databaseProvider, "Postgres", StringComparison.OrdinalIgnoreCase)
        || connectionString.Contains("Host=", StringComparison.OrdinalIgnoreCase)
        || connectionString.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)
        || connectionString.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase);

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

    /// <summary>
    /// Validates DNS lookup settings before HIP starts so bad resolver configuration fails clearly.
    /// </summary>
    /// <param name="options">DNS verification options.</param>
    /// <returns>True when options are safe to use.</returns>
    private static bool ValidateDnsVerificationOptions(DnsVerificationOptions options) =>
        options.TimeoutMilliseconds is >= 500 and <= 15000
        && (options.NameServerPort is null or (> 0 and <= 65535))
        && (string.IsNullOrWhiteSpace(options.NameServerHost) || System.Net.IPAddress.TryParse(options.NameServerHost, out _));
}
