using HIP.Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>Defines indexed, non-secret persistence for domain enrollments and certificate history.</summary>
internal static class DomainCertificateModelConfiguration
{
    /// <summary>Applies certificate tables, constraints, concurrency tokens, and lookup indexes.</summary>
    internal static void Configure(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<HipDomainEnrollmentEntity>(entity =>
        {
            entity.ToTable("hip_domain_enrollments");
            entity.HasKey(item => item.EnrollmentId);
            entity.Property(item => item.EnrollmentId).HasMaxLength(128);
            entity.Property(item => item.OwnerId).HasMaxLength(256).IsRequired();
            entity.Property(item => item.Domain).HasMaxLength(253).IsRequired();
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(64);
            entity.Property(item => item.PolicyVersion).HasMaxLength(128).IsRequired();
            entity.Property(item => item.PublicDisplayName).HasMaxLength(200);
            entity.Property(item => item.PublicOrganizationName).HasMaxLength(200);
            entity.Property(item => item.PublicWebsiteContact).HasMaxLength(320);
            entity.Property(item => item.PublicCountryOrRegion).HasMaxLength(100);
            entity.Property(item => item.SecurityContactHash).HasMaxLength(71);
            entity.Property(item => item.ApplicationStatus).HasConversion<string>().HasMaxLength(32).HasDefaultValue(HIP.Domain.Certificates.DomainCertificateApplicationStatus.Draft);
            entity.Property(item => item.ApplicantAttestationDigest).HasMaxLength(71);
            entity.Property(item => item.ApplicationDecisionReason).HasMaxLength(500);
            entity.HasIndex(item => item.ApplicationStatus);
            entity.Property(item => item.AggregateVersion).IsConcurrencyToken();
            entity.HasIndex(item => item.Domain).IsUnique().HasFilter("\"IsCurrent\" = TRUE");
            entity.HasIndex(item => item.OwnerId);
            entity.HasIndex(item => item.Status);
            entity.HasIndex(item => new { item.MonitoringEnabledAtUtc, item.MonitoringNextCheckAtUtc })
                .HasDatabaseName("IX_hip_domain_enrollments_monitoring_due");
        });

        modelBuilder.Entity<HipDomainCertificateEntity>(entity =>
        {
            entity.ToTable("hip_domain_certificates");
            entity.HasKey(item => item.CertificateId);
            entity.Property(item => item.CertificateId).HasMaxLength(128);
            entity.Property(item => item.EnrollmentId).HasMaxLength(128).IsRequired();
            entity.Property(item => item.OwnerId).HasMaxLength(256).IsRequired();
            entity.Property(item => item.Domain).HasMaxLength(253).IsRequired();
            entity.Property(item => item.Level).HasConversion<string>().HasMaxLength(32);
            entity.Property(item => item.Status).HasConversion<string>().HasMaxLength(64);
            entity.Property(item => item.PolicyVersion).HasMaxLength(128).IsRequired();
            entity.Property(item => item.SigningKeyId).HasMaxLength(128);
            entity.Property(item => item.SignatureAlgorithm).HasMaxLength(128);
            entity.Property(item => item.PublicDisplayName).HasMaxLength(200);
            entity.Property(item => item.PublicOrganizationName).HasMaxLength(200);
            entity.Property(item => item.PublicRiskClassification).HasMaxLength(80);
            entity.Property(item => item.SigningAuthorityId).HasMaxLength(256);
            entity.Property(item => item.PublicCertificateUrl).HasMaxLength(512);
            entity.Property(item => item.SignatureAlgorithmFamily).HasMaxLength(80);
            entity.Property(item => item.SignatureCanonicalization).HasMaxLength(80);
            entity.Property(item => item.RegistrantPublicKeyId).HasMaxLength(128);
            entity.Property(item => item.CertificateDigest).HasMaxLength(71);
            entity.Property(item => item.SourceDecisionDigest).HasMaxLength(71);
            entity.Property(item => item.RevocationStatusUrl).HasMaxLength(512);
            entity.Property(item => item.AggregateVersion).IsConcurrencyToken();
            entity.HasIndex(item => item.Domain).IsUnique().HasFilter("\"IsCurrent\" = TRUE");
            entity.HasIndex(item => item.OwnerId);
            entity.HasIndex(item => item.Status);
            entity.HasIndex(item => item.ExpiresAtUtc);
            entity.HasIndex(item => item.EnrollmentId);
            entity.HasOne<HipDomainEnrollmentEntity>()
                .WithMany()
                .HasForeignKey(item => item.EnrollmentId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<HipDomainCertificateEventEntity>(entity =>
        {
            entity.ToTable("hip_domain_certificate_events");
            entity.HasKey(item => item.EventId);
            entity.Property(item => item.EventId).HasMaxLength(128);
            entity.Property(item => item.EnrollmentId).HasMaxLength(128).IsRequired();
            entity.Property(item => item.CertificateId).HasMaxLength(128);
            entity.Property(item => item.EventType).HasMaxLength(80).IsRequired();
            entity.Property(item => item.PreviousStatus).HasMaxLength(64);
            entity.Property(item => item.CurrentStatus).HasMaxLength(64).IsRequired();
            entity.Property(item => item.ActorId).HasMaxLength(256).IsRequired();
            entity.Property(item => item.ReasonCode).HasMaxLength(120);
            entity.Property(item => item.PublicSummary).HasMaxLength(500);
            entity.Property(item => item.PolicyVersion).HasMaxLength(128).IsRequired();
            entity.Property(item => item.EvidenceDigest).HasMaxLength(71);
            entity.HasIndex(item => new { item.CertificateId, item.OccurredAtUtc });
            entity.HasIndex(item => new { item.EnrollmentId, item.OccurredAtUtc });
            entity.HasOne<HipDomainEnrollmentEntity>()
                .WithMany()
                .HasForeignKey(item => item.EnrollmentId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<HipDomainCertificateEntity>()
                .WithMany()
                .HasForeignKey(item => item.CertificateId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }
}
