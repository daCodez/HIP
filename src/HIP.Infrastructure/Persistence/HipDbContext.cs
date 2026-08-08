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
    /// Gets immutable signed trust receipts and their indexed authoritative-evaluation identities.
    /// </summary>
    public DbSet<HipTrustReceiptEntity> TrustReceipts => Set<HipTrustReceiptEntity>();

    /// <summary>Gets indexed domain-owner enrollment state.</summary>
    public DbSet<HipDomainEnrollmentEntity> DomainEnrollments => Set<HipDomainEnrollmentEntity>();

    /// <summary>Gets versioned HIP Domain Trust Certificate records.</summary>
    public DbSet<HipDomainCertificateEntity> DomainCertificates => Set<HipDomainCertificateEntity>();

    /// <summary>Gets the append-only domain certificate audit trail.</summary>
    public DbSet<HipDomainCertificateEventEntity> DomainCertificateEvents => Set<HipDomainCertificateEventEntity>();

    /// <summary>Gets stable managed domains shared by individual and organization accounts.</summary>
    public DbSet<HipManagedDomainEntity> ManagedDomains => Set<HipManagedDomainEntity>();

    /// <summary>Gets domain-management organizations.</summary>
    public DbSet<HipDomainOrganizationEntity> DomainOrganizations => Set<HipDomainOrganizationEntity>();

    /// <summary>Gets organization-wide domain memberships.</summary>
    public DbSet<HipOrganizationMembershipEntity> OrganizationMemberships => Set<HipOrganizationMembershipEntity>();

    /// <summary>Gets direct per-domain access grants.</summary>
    public DbSet<HipManagedDomainAccessEntity> ManagedDomainAccess => Set<HipManagedDomainAccessEntity>();

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
            entity.Property(record => record.AggregateVersion)
                .HasDefaultValue(0L)
                .IsConcurrencyToken();
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

        modelBuilder.Entity<HipTrustReceiptEntity>(entity =>
        {
            entity.ToTable("hip_trust_receipts");
            entity.HasKey(receipt => receipt.ReceiptId);
            entity.Property(receipt => receipt.ReceiptId).HasMaxLength(128);
            entity.Property(receipt => receipt.RelatedEvaluationId).HasMaxLength(256).IsRequired();
            entity.Property(receipt => receipt.ReceiptJson).IsRequired();
            entity.Property(receipt => receipt.ReceiptDigest).HasMaxLength(71).IsRequired();
            entity.Property(receipt => receipt.SourceEvaluationDigest).HasMaxLength(71).IsRequired();
            entity.Property(receipt => receipt.DocumentType).HasMaxLength(64).IsRequired();
            entity.Property(receipt => receipt.ProtocolVersion).HasMaxLength(32).IsRequired();
            entity.Property(receipt => receipt.SubjectType).HasMaxLength(64).IsRequired();
            entity.Property(receipt => receipt.SubjectId).HasMaxLength(512).IsRequired();
            entity.Property(receipt => receipt.PolicyVersion).HasMaxLength(128).IsRequired();
            entity.Property(receipt => receipt.RuleSetVersion).HasMaxLength(128).IsRequired();
            entity.Property(receipt => receipt.EvidenceDigest).HasMaxLength(71).IsRequired();
            entity.Property(receipt => receipt.IssuerId).HasMaxLength(256).IsRequired();
            entity.Property(receipt => receipt.KeyId).HasMaxLength(128).IsRequired();
            entity.Property(receipt => receipt.Algorithm).HasMaxLength(128).IsRequired();
            entity.HasIndex(receipt => receipt.RelatedEvaluationId).IsUnique();
            entity.HasIndex(receipt => receipt.SubjectId);
            entity.HasIndex(receipt => receipt.ExpiresAtUtc);
            entity.HasIndex(receipt => receipt.IssuerId);
        });

        DomainCertificateModelConfiguration.Configure(modelBuilder);
        ManagedDomainModelConfiguration.Configure(modelBuilder);
    }
}
