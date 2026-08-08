using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>Defines additive persistence for the unified managed-domain registry.</summary>
internal static class ManagedDomainModelConfiguration
{
    internal static void Configure(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HipDomainOrganizationEntity>(entity =>
        {
            entity.ToTable("hip_domain_organizations");
            entity.HasKey(item => item.OrganizationId);
            entity.Property(item => item.OrganizationId).HasMaxLength(256);
            entity.Property(item => item.Name).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Version).IsConcurrencyToken();
            entity.HasIndex(item => item.Name);
        });

        modelBuilder.Entity<HipManagedDomainEntity>(entity =>
        {
            entity.ToTable("hip_managed_domains");
            entity.HasKey(item => item.DomainId);
            entity.Property(item => item.DomainId).HasMaxLength(256);
            entity.Property(item => item.DomainName).HasMaxLength(253).IsRequired();
            entity.Property(item => item.OwnerId).HasMaxLength(256).IsRequired();
            entity.Property(item => item.OrganizationId).HasMaxLength(256);
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.DnssecStatus).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.DnssecDiagnostic).HasMaxLength(500);
            entity.Property(item => item.VerificationStatus)
                .HasConversion<string>()
                .HasMaxLength(32)
                .HasDefaultValue(HIP.Domain.Domains.ManagedDomainVerificationStatus.Unverified);
            entity.Property(item => item.VerificationMethod).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.Version).IsConcurrencyToken();
            entity.HasIndex(item => item.DomainName).IsUnique();
            entity.HasIndex(item => item.OwnerId);
            entity.HasIndex(item => item.OrganizationId);
            entity.HasIndex(item => item.Status);
            entity.HasOne<HipDomainOrganizationEntity>()
                .WithMany()
                .HasForeignKey(item => item.OrganizationId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<HipManagedDomainVerificationEventEntity>(entity =>
        {
            entity.ToTable("hip_managed_domain_verification_events");
            entity.HasKey(item => item.EventId);
            entity.Property(item => item.EventId).HasMaxLength(128);
            entity.Property(item => item.DomainId).HasMaxLength(256).IsRequired();
            entity.Property(item => item.Method).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.EventType).HasMaxLength(64).IsRequired();
            entity.Property(item => item.Outcome).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.TokenDigest).HasMaxLength(71).IsRequired();
            entity.HasIndex(item => new { item.DomainId, item.OccurredAtUtc });
            entity.HasOne<HipManagedDomainEntity>()
                .WithMany()
                .HasForeignKey(item => item.DomainId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<HipOrganizationMembershipEntity>(entity =>
        {
            entity.ToTable("hip_organization_memberships");
            entity.HasKey(item => new { item.OrganizationId, item.UserId });
            entity.Property(item => item.OrganizationId).HasMaxLength(256);
            entity.Property(item => item.UserId).HasMaxLength(256);
            entity.Property(item => item.Role).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(item => item.UserId);
            entity.HasOne<HipDomainOrganizationEntity>()
                .WithMany()
                .HasForeignKey(item => item.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<HipManagedDomainAccessEntity>(entity =>
        {
            entity.ToTable("hip_managed_domain_access");
            entity.HasKey(item => new { item.DomainId, item.UserId });
            entity.Property(item => item.DomainId).HasMaxLength(256);
            entity.Property(item => item.UserId).HasMaxLength(256);
            entity.Property(item => item.Role).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(item => item.UserId);
            entity.HasOne<HipManagedDomainEntity>()
                .WithMany()
                .HasForeignKey(item => item.DomainId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
