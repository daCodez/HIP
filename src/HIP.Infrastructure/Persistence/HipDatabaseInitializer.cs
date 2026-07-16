using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Selects the only two supported database startup behaviors.
/// </summary>
public enum HipDatabaseInitializationMode
{
    /// <summary>
    /// Creates and additively patches an explicitly local Development schema.
    /// </summary>
    CreateDevelopmentSchema,

    /// <summary>
    /// Validates that every compiled migration was applied by a separate operator action.
    /// </summary>
    ValidateMigrations
}

/// <summary>
/// Initializes HIP's database without silently creating production schema.
/// </summary>
public static class HipDatabaseInitializer
{
    /// <summary>
    /// Initializes local Development storage or validates a production-like schema without mutating it.
    /// </summary>
    /// <param name="services">Application service provider.</param>
    /// <param name="mode">Explicit database initialization behavior.</param>
    /// <param name="cancellationToken">Token used to cancel initialization.</param>
    /// <exception cref="InvalidOperationException">Thrown when migration state is missing, pending, or cannot be validated.</exception>
    public static async Task InitializeAsync(
        IServiceProvider services,
        HipDatabaseInitializationMode mode,
        CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<HipDbContext>();

        switch (mode)
        {
            case HipDatabaseInitializationMode.CreateDevelopmentSchema:
                await dbContext.Database.EnsureCreatedAsync(cancellationToken);
                await EnsureDevelopmentTablesAsync(dbContext, cancellationToken);
                return;
            case HipDatabaseInitializationMode.ValidateMigrations:
                await ValidateMigrationsAsync(dbContext, cancellationToken);
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported HIP database initialization mode.");
        }
    }

    /// <summary>
    /// Compatibility wrapper for callers that have not yet adopted the explicit initialization mode.
    /// </summary>
    [Obsolete("Use InitializeAsync with an explicit HipDatabaseInitializationMode.")]
    public static Task EnsureCreatedAsync(
        IServiceProvider services,
        bool isLocalDevelopment,
        CancellationToken cancellationToken = default) =>
        InitializeAsync(
            services,
            isLocalDevelopment
                ? HipDatabaseInitializationMode.CreateDevelopmentSchema
                : HipDatabaseInitializationMode.ValidateMigrations,
            cancellationToken);

    private static async Task ValidateMigrationsAsync(HipDbContext dbContext, CancellationToken cancellationToken)
    {
        var migrations = dbContext.Database.GetMigrations().ToArray();
        if (migrations.Length == 0)
        {
            throw new InvalidOperationException(
                "HIP database migrations are required outside local Development; no compiled migrations were found.");
        }

        string[] pendingMigrations;
        try
        {
            pendingMigrations = (await dbContext.Database.GetPendingMigrationsAsync(cancellationToken)).ToArray();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException(
                "HIP could not validate the database migration state. Verify database connectivity and migration-history access.",
                exception);
        }

        if (pendingMigrations.Length > 0)
        {
            throw new InvalidOperationException(
                $"HIP database migrations must be applied before application startup. Pending: {string.Join(", ", pendingMigrations)}. " +
                "Apply them through the reviewed EF migration command documented in docs/persistence.md.");
        }
    }

    /// <summary>
    /// Adds missing local development tables to an existing database without destroying current data.
    /// </summary>
    /// <param name="dbContext">HIP database context.</param>
    /// <param name="cancellationToken">Token used to cancel schema initialization.</param>
    /// <remarks>
    /// EF Core <c>EnsureCreated</c> does not evolve an already-created database. HIP uses this additive development
    /// initializer until formal migrations are introduced, so local PostgreSQL databases receive both the generic
    /// encrypted record table and typed scan tables without wiping existing local data.
    /// </remarks>
    private static async Task EnsureDevelopmentTablesAsync(HipDbContext dbContext, CancellationToken cancellationToken)
    {
        var providerName = dbContext.Database.ProviderName ?? string.Empty;
        if (providerName.Contains("Npgsql", StringComparison.OrdinalIgnoreCase))
        {
            await EnsurePostgreSqlDevelopmentTablesAsync(dbContext, cancellationToken);
            return;
        }

        if (providerName.Contains("InMemory", StringComparison.OrdinalIgnoreCase))
        {
            // Test hosts use EF's in-memory provider after production startup validation has already required an explicit
            // PostgreSQL connection string. There is no relational schema to patch in that provider, so initialization ends here.
            return;
        }

        throw new InvalidOperationException("HIP development schema initialization requires PostgreSQL.");
    }

    /// <summary>
    /// Creates PostgreSQL development tables and indexes when missing.
    /// </summary>
    /// <param name="dbContext">HIP database context.</param>
    /// <param name="cancellationToken">Token used to cancel schema initialization.</param>
    private static async Task EnsurePostgreSqlDevelopmentTablesAsync(HipDbContext dbContext, CancellationToken cancellationToken)
    {
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_records (
                "Partition" character varying(160) NOT NULL,
                "Id" character varying(220) NOT NULL,
                "Json" text NOT NULL,
                "CreatedAtUtc" timestamp with time zone NOT NULL,
                "UpdatedAtUtc" timestamp with time zone NOT NULL,
                CONSTRAINT "PK_hip_records" PRIMARY KEY ("Partition", "Id")
            );
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_browser_scan_results (
                "ScanResultId" character varying(220) NOT NULL,
                "Domain" character varying(253) NOT NULL,
                "PageUrlHash" character varying(96) NOT NULL,
                "StoredPageUrl" character varying(2048) NULL,
                "ScanSource" character varying(80) NOT NULL,
                "Score" integer NOT NULL,
                "RiskLevel" character varying(80) NOT NULL,
                "Status" character varying(80) NOT NULL,
                "ReasonsJson" text NOT NULL,
                "LinksScanned" integer NOT NULL,
                "RiskyLinksFound" integer NOT NULL,
                "SuspiciousLinksFound" integer NOT NULL,
                "DangerousLinksFound" integer NOT NULL,
                "LastCheckedUtc" timestamp with time zone NOT NULL,
                "RecommendedAction" character varying(120) NOT NULL,
                "PrivacySafeMetadataJson" text NOT NULL,
                "PluginVersion" character varying(80) NULL,
                "CreatedAtUtc" timestamp with time zone NOT NULL,
                "UpdatedAtUtc" timestamp with time zone NOT NULL,
                CONSTRAINT "PK_hip_browser_scan_results" PRIMARY KEY ("ScanResultId")
            );
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_dashboard_scan_aggregates (
                "Id" character varying(80) NOT NULL,
                "TotalScans" integer NOT NULL,
                "ScansToday" integer NOT NULL,
                "Trusted" integer NOT NULL,
                "MostlyTrusted" integer NOT NULL,
                "LimitedTrustData" integer NOT NULL,
                "Unknown" integer NOT NULL,
                "Suspicious" integer NOT NULL,
                "HighRisk" integer NOT NULL,
                "Dangerous" integer NOT NULL,
                "UpdatedAtUtc" timestamp with time zone NOT NULL,
                CONSTRAINT "PK_hip_dashboard_scan_aggregates" PRIMARY KEY ("Id")
            );
            """,
            cancellationToken);

        await CreateIndexesAsync(dbContext, cancellationToken);
    }

    /// <summary>
    /// Creates provider-neutral indexes for typed scan and aggregate tables.
    /// </summary>
    /// <param name="dbContext">HIP database context.</param>
    /// <param name="cancellationToken">Token used to cancel schema initialization.</param>
    private static async Task CreateIndexesAsync(HipDbContext dbContext, CancellationToken cancellationToken)
    {
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_records_UpdatedAtUtc"
            ON hip_records ("UpdatedAtUtc");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_browser_scan_results_Domain"
            ON hip_browser_scan_results ("Domain");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_browser_scan_results_LastCheckedUtc"
            ON hip_browser_scan_results ("LastCheckedUtc");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_browser_scan_results_Domain_LastCheckedUtc"
            ON hip_browser_scan_results ("Domain", "LastCheckedUtc");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_browser_scan_results_Status"
            ON hip_browser_scan_results ("Status");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_browser_scan_results_RiskLevel"
            ON hip_browser_scan_results ("RiskLevel");
            """,
            cancellationToken);
        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE INDEX IF NOT EXISTS "IX_hip_dashboard_scan_aggregates_UpdatedAtUtc"
            ON hip_dashboard_scan_aggregates ("UpdatedAtUtc");
            """,
            cancellationToken);
    }
}
