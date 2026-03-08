using Microsoft.EntityFrameworkCore;

namespace HIP.Security.Infrastructure.Persistence;

public sealed class SecurityAuditDbContext(DbContextOptions<SecurityAuditDbContext> options) : DbContext(options)
{
    public DbSet<PolicyAuditRecordEntity> PolicyAuditEvents => Set<PolicyAuditRecordEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new PolicyAuditRecordEntityConfiguration());
        base.OnModelCreating(modelBuilder);
    }
}
