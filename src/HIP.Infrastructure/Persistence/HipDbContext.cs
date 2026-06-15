using Microsoft.EntityFrameworkCore;
using HIP.Infrastructure.Persistence.Entities;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// EF Core context for HIP persistence.
/// </summary>
/// <remarks>
/// The generic encrypted record table remains available for lower-volume domain objects, while typed hot-path tables
/// hold scan and dashboard projection data that must be queried without decrypting every historical row.
/// </remarks>
public sealed class HipDbContext(DbContextOptions<HipDbContext> options) : DbContext(options)
{
    /// <summary>
    /// Gets the generic encrypted JSON records used by lower-volume repositories.
    /// </summary>
    public DbSet<HipDbRecord> Records => Set<HipDbRecord>();

    /// <summary>
    /// Gets typed browser scan results for public lookup and dashboard hot paths.
    /// </summary>
    public DbSet<HipBrowserScanResultEntity> BrowserScanResults => Set<HipBrowserScanResultEntity>();

    /// <summary>
    /// Gets pre-aggregated dashboard scan counters.
    /// </summary>
    public DbSet<HipDashboardScanAggregateEntity> DashboardScanAggregates => Set<HipDashboardScanAggregateEntity>();

    /// <summary>
    /// Configures table names, keys, lengths, and indexes for HIP persistence.
    /// </summary>
    /// <param name="modelBuilder">EF Core model builder.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HipDbRecord>(entity =>
        {
            entity.ToTable("hip_records");
            entity.HasKey(record => new { record.Partition, record.Id });
            entity.Property(record => record.Partition).HasMaxLength(160);
            entity.Property(record => record.Id).HasMaxLength(220);
            entity.Property(record => record.Json).IsRequired();
            entity.HasIndex(record => record.UpdatedAtUtc);
        });

        modelBuilder.Entity<HipBrowserScanResultEntity>(entity =>
        {
            entity.ToTable("hip_browser_scan_results");
            entity.HasKey(scan => scan.ScanResultId);
            entity.Property(scan => scan.ScanResultId).HasMaxLength(220);
            entity.Property(scan => scan.Domain).HasMaxLength(253).IsRequired();
            entity.Property(scan => scan.PageUrlHash).HasMaxLength(96).IsRequired();
            entity.Property(scan => scan.StoredPageUrl).HasMaxLength(2048);
            entity.Property(scan => scan.ScanSource).HasMaxLength(80).IsRequired();
            entity.Property(scan => scan.RiskLevel).HasMaxLength(80).IsRequired();
            entity.Property(scan => scan.Status).HasMaxLength(80).IsRequired();
            entity.Property(scan => scan.ReasonsJson).IsRequired();
            entity.Property(scan => scan.RecommendedAction).HasMaxLength(120).IsRequired();
            entity.Property(scan => scan.PrivacySafeMetadataJson).IsRequired();
            entity.Property(scan => scan.PluginVersion).HasMaxLength(80);
            entity.HasIndex(scan => scan.Domain);
            entity.HasIndex(scan => scan.LastCheckedUtc);
            entity.HasIndex(scan => new { scan.Domain, scan.LastCheckedUtc });
            entity.HasIndex(scan => scan.Status);
            entity.HasIndex(scan => scan.RiskLevel);
        });

        modelBuilder.Entity<HipDashboardScanAggregateEntity>(entity =>
        {
            entity.ToTable("hip_dashboard_scan_aggregates");
            entity.HasKey(aggregate => aggregate.Id);
            entity.Property(aggregate => aggregate.Id).HasMaxLength(80);
            entity.HasIndex(aggregate => aggregate.UpdatedAtUtc);
        });
    }
}
