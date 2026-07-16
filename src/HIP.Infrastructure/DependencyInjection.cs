using HIP.Application.Browser;
using HIP.Application.Identity;
using HIP.Application.Platforms;
using HIP.Application.Reporting;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Security;
using HIP.Application.SecondLife;
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
        var recordEncryptionOptions = BindRecordEncryptionOptions(configuration, isLocalDevelopment);
        var privacyHashingOptions = BindPrivacyHashingOptions(configuration, isLocalDevelopment);
        ValidateSecurityKeySeparation(recordEncryptionOptions, privacyHashingOptions, isLocalDevelopment);
        services.AddSingleton(recordEncryptionOptions);
        services.AddSingleton(privacyHashingOptions);
        services.AddSingleton<IHipRecordEncryptor, DevelopmentHipRecordEncryptor>();
        services.AddScoped<HipRecordStore>();
        services.AddOptions<DnsVerificationOptions>()
            .Bind(configuration.GetSection(DnsVerificationOptions.SectionName))
            .Validate(ValidateDnsVerificationOptions, "DNS verification options must use a valid port and timeout.")
            .ValidateOnStart();
        services.AddSingleton<IDnsTxtRecordResolver, DnsClientTxtRecordResolver>();

        services.AddScoped<IHipIdentityRepository, EfHipIdentityRepository>();
        services.AddScoped<IDomainVerificationRequestRepository, EfDomainVerificationRequestRepository>();
        services.AddScoped<IWebsiteIdentityRepository, EfWebsiteIdentityRepository>();
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
        services.AddScoped<IDuplicateSubmissionGuard, EfDuplicateSubmissionGuard>();
        services.AddScoped<ISetupCodeLicenseService, EfSetupCodeLicenseService>();
        services.AddScoped<IExternalSiteEvidenceCache, EfExternalSiteEvidenceCache>();
        services.AddScoped<IExternalSiteEvidenceSettingsStore, EfExternalSiteEvidenceSettingsStore>();
        services.AddScoped<IExternalProviderResiliencePolicy, EfExternalProviderResiliencePolicy>();
        services.AddScoped<IScanResultCache, EfScanResultCache>();
        services.AddScoped<IScanIngestionQueue, EfScanIngestionQueue>();
        services.AddScoped<ISandboxLinkScanQueue, EfSandboxLinkScanQueue>();
        services.AddScoped<IScanResultDedupeService, EfScanResultDedupeService>();
        services.AddScoped<IDashboardScanAggregateStore, EfDashboardScanAggregateStore>();
        services.AddScoped<IPlatformConnectionRepository, EfPlatformConnectionRepository>();

        return services;
    }

    /// <summary>
    /// Selects the EF Core provider from configuration. HIP runtime persistence is PostgreSQL-only so scan,
    /// identity, and verification data cannot disappear when the process restarts.
    /// </summary>
    /// <param name="options">EF Core options builder being configured for HIP persistence.</param>
    /// <param name="connectionString">Database connection string supplied by configuration or Aspire service discovery.</param>
    /// <param name="databaseProvider">Optional provider name, such as PostgreSQL.</param>
    private static void ConfigureDatabaseProvider(
        DbContextOptionsBuilder options,
        string connectionString,
        string? databaseProvider)
    {
        if (!ShouldUsePostgreSql(connectionString, databaseProvider))
        {
            throw new InvalidOperationException(
                "HIP runtime persistence requires PostgreSQL. Run HIP.AppHost to use Aspire-managed PostgreSQL, or set ConnectionStrings__HipDatabase to a PostgreSQL connection string.");
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
    private static HipRecordEncryptionOptions BindRecordEncryptionOptions(IConfiguration configuration, bool isLocalDevelopment)
    {
        var key = ResolveSecurityKey(
            configuration,
            "HipSecurity:RecordEncryptionKey",
            DevelopmentHipRecordEncryptor.DevelopmentOnlyKey,
            isLocalDevelopment);

        return new(
            key,
            AllowDevelopmentKey: isLocalDevelopment,
            LegacyKeys: BindLegacyRecordEncryptionKeys(configuration, isLocalDevelopment));
    }

    /// <summary>
    /// Binds legacy record encryption keys that may read older local rows after a development key rotation.
    /// </summary>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="isLocalDevelopment">Whether local development compatibility fallbacks may be used.</param>
    /// <returns>Configured legacy keys plus the former built-in development key for local compatibility.</returns>
    private static IReadOnlyCollection<string> BindLegacyRecordEncryptionKeys(IConfiguration configuration, bool isLocalDevelopment)
    {
        var configured = configuration
            .GetSection("HipSecurity:LegacyRecordEncryptionKeys")
            .Get<string[]>() ?? [];
        if (!isLocalDevelopment)
        {
            foreach (var legacyKey in configured)
            {
                EnsureProductionSecurityKey(
                    legacyKey,
                    "HipSecurity:LegacyRecordEncryptionKeys",
                    DevelopmentHipRecordEncryptor.DevelopmentOnlyKey);
            }

            return configured;
        }

        var currentKey = ResolveSecurityKey(
            configuration,
            "HipSecurity:RecordEncryptionKey",
            DevelopmentHipRecordEncryptor.DevelopmentOnlyKey,
            isLocalDevelopment);
        return configured
            .Append(DevelopmentHipRecordEncryptor.DevelopmentOnlyKey)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Where(key => !string.Equals(key, currentKey, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Binds privacy HMAC settings and disables default keys outside local Development.
    /// </summary>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="isLocalDevelopment">Whether the host is a local Development process.</param>
    /// <returns>Privacy hashing options.</returns>
    private static PrivacyHashingOptions BindPrivacyHashingOptions(IConfiguration configuration, bool isLocalDevelopment) =>
        new(
            ResolveSecurityKey(
                configuration,
                "HipSecurity:PrivacyHashingKey",
                Sha256PrivacyHashingService.DevelopmentOnlyKey,
                isLocalDevelopment),
            AllowDevelopmentKey: isLocalDevelopment);

    /// <summary>
    /// Resolves one security key and rejects missing, shared, weak, or placeholder material outside Development.
    /// </summary>
    /// <param name="configuration">Application configuration.</param>
    /// <param name="settingName">Configuration path used in safe error messages.</param>
    /// <param name="developmentKey">Built-in key permitted only for explicit local Development.</param>
    /// <param name="isLocalDevelopment">Whether the host is an explicit local Development process.</param>
    /// <returns>The configured key, or the built-in fallback only in local Development.</returns>
    /// <exception cref="InvalidOperationException">Thrown when production key material is unsafe.</exception>
    private static string ResolveSecurityKey(
        IConfiguration configuration,
        string settingName,
        string developmentKey,
        bool isLocalDevelopment)
    {
        var configuredKey = configuration[settingName];
        if (isLocalDevelopment)
        {
            return configuredKey ?? developmentKey;
        }

        EnsureProductionSecurityKey(configuredKey, settingName, developmentKey);
        return configuredKey!;
    }

    /// <summary>
    /// Rejects unsafe production secret material without exposing the configured value.
    /// </summary>
    /// <param name="configuredKey">Secret value to validate.</param>
    /// <param name="settingName">Configuration path used in safe error messages.</param>
    /// <param name="developmentKey">Built-in value that is never valid in production.</param>
    /// <exception cref="InvalidOperationException">Thrown when the value is missing, weak, shared, or a placeholder.</exception>
    private static void EnsureProductionSecurityKey(
        string? configuredKey,
        string settingName,
        string developmentKey)
    {
        if (string.IsNullOrWhiteSpace(configuredKey)
            || configuredKey.Length < 32
            || string.Equals(configuredKey, developmentKey, StringComparison.Ordinal)
            || configuredKey.Contains("CHANGE-BEFORE-PRODUCTION", StringComparison.OrdinalIgnoreCase)
            || configuredKey.Contains("placeholder", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{settingName} must contain at least 32 characters of non-placeholder secret material outside local Development.");
        }
    }

    /// <summary>
    /// Prevents one production secret from being reused across encryption and privacy hashing.
    /// </summary>
    /// <param name="recordEncryptionOptions">Validated record-encryption options.</param>
    /// <param name="privacyHashingOptions">Validated privacy-hashing options.</param>
    /// <param name="isLocalDevelopment">Whether the host is an explicit local Development process.</param>
    /// <exception cref="InvalidOperationException">Thrown when production key separation is violated.</exception>
    private static void ValidateSecurityKeySeparation(
        HipRecordEncryptionOptions recordEncryptionOptions,
        PrivacyHashingOptions privacyHashingOptions,
        bool isLocalDevelopment)
    {
        if (!isLocalDevelopment
            && string.Equals(recordEncryptionOptions.Key, privacyHashingOptions.SecretKey, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "HipSecurity:RecordEncryptionKey and HipSecurity:PrivacyHashingKey must be different outside local Development.");
        }
    }

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
