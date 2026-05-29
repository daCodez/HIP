using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

public sealed class HipDbContext(DbContextOptions<HipDbContext> options) : DbContext(options)
{
    public DbSet<HipDbRecord> Records => Set<HipDbRecord>();

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
    }
}
