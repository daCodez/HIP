using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Initializes HIP's database without silently creating production schema.
/// </summary>
public static class HipDatabaseInitializer
{
    /// <summary>
    /// Creates a local development database or applies migrations when running outside Development.
    /// </summary>
    /// <param name="services">Application service provider.</param>
    /// <param name="isLocalDevelopment">Whether local Development schema creation is allowed.</param>
    /// <param name="cancellationToken">Token used to cancel initialization.</param>
    /// <exception cref="InvalidOperationException">Thrown outside Development when no EF migrations are configured.</exception>
    public static async Task EnsureCreatedAsync(IServiceProvider services, bool isLocalDevelopment = true, CancellationToken cancellationToken = default)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<HipDbContext>();
        if (isLocalDevelopment)
        {
            await dbContext.Database.EnsureCreatedAsync(cancellationToken);
            await EnsureDevelopmentTablesAsync(dbContext, cancellationToken);
            return;
        }

        var migrations = dbContext.Database.GetMigrations();
        if (!migrations.Any())
        {
            throw new InvalidOperationException("HIP database migrations are required outside local Development; refusing EnsureCreated.");
        }

        await dbContext.Database.MigrateAsync(cancellationToken);
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
