using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace HIP.Security.Infrastructure.Persistence;

public sealed class PolicyAuditRecordEntity
{
    public Guid EventId { get; init; }
    public Guid PolicyId { get; init; }
    public string Action { get; init; } = string.Empty;
    public string Outcome { get; init; } = string.Empty;
    public string? ReasonCode { get; init; }
    public DateTimeOffset OccurredAtUtc { get; init; }
    public string MetadataJson { get; init; } = "{}";
    public DateTimeOffset AppendedAtUtc { get; init; }
}

internal sealed class PolicyAuditRecordEntityConfiguration : IEntityTypeConfiguration<PolicyAuditRecordEntity>
{
    public void Configure(EntityTypeBuilder<PolicyAuditRecordEntity> builder)
    {
        builder.ToTable("PolicyAuditEvents");
        builder.HasKey(x => x.EventId);
        builder.Property(x => x.Action).HasMaxLength(128).IsRequired();
        builder.Property(x => x.Outcome).HasMaxLength(64).IsRequired();
        builder.Property(x => x.ReasonCode).HasMaxLength(128);
        builder.Property(x => x.MetadataJson).IsRequired();
        builder.Property(x => x.OccurredAtUtc).IsRequired();
        builder.Property(x => x.AppendedAtUtc).IsRequired();

        builder.HasIndex(x => x.PolicyId);
        builder.HasIndex(x => x.OccurredAtUtc);
    }
}
