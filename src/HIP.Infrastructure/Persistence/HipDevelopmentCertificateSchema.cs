using Microsoft.EntityFrameworkCore;

namespace HIP.Infrastructure.Persistence;

/// <summary>
/// Additively repairs local Development databases that predate domain-certificate persistence.
/// </summary>
internal static class HipDevelopmentCertificateSchema
{
    /// <summary>
    /// Creates the current certificate tables, upgrade columns, foreign keys, and lookup indexes when missing.
    /// </summary>
    /// <param name="dbContext">HIP database context.</param>
    /// <param name="cancellationToken">Token used to cancel schema initialization.</param>
    internal static async Task EnsureAsync(HipDbContext dbContext, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dbContext);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_domain_enrollments (
                "EnrollmentId" character varying(128) NOT NULL,
                "OwnerId" character varying(256) NOT NULL,
                "Domain" character varying(253) NOT NULL,
                "Status" character varying(64) NOT NULL,
                "PolicyVersion" character varying(128) NOT NULL,
                "IsCurrent" boolean NOT NULL,
                "CreatedAtUtc" timestamp with time zone NOT NULL,
                "UpdatedAtUtc" timestamp with time zone NOT NULL,
                "DnsVerifiedAtUtc" timestamp with time zone NULL,
                "WebsiteVerifiedAtUtc" timestamp with time zone NULL,
                "IdentityCompletedAtUtc" timestamp with time zone NULL,
                "SecurityReviewCompletedAtUtc" timestamp with time zone NULL,
                "LastMonitoringAtUtc" timestamp with time zone NULL,
                "CurrentScore" integer NULL,
                "UnresolvedCriticalFindings" integer NOT NULL,
                "AggregateVersion" bigint NOT NULL,
                "PublicCountryOrRegion" character varying(100) NULL,
                "PublicDisplayName" character varying(200) NULL,
                "PublicOrganizationName" character varying(200) NULL,
                "PublicWebsiteContact" character varying(320) NULL,
                "SecurityContactHash" character varying(71) NULL,
                CONSTRAINT "PK_hip_domain_enrollments" PRIMARY KEY ("EnrollmentId")
            );
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            ALTER TABLE hip_domain_enrollments
                ADD COLUMN IF NOT EXISTS "PublicCountryOrRegion" character varying(100) NULL,
                ADD COLUMN IF NOT EXISTS "PublicDisplayName" character varying(200) NULL,
                ADD COLUMN IF NOT EXISTS "PublicOrganizationName" character varying(200) NULL,
                ADD COLUMN IF NOT EXISTS "PublicWebsiteContact" character varying(320) NULL,
                ADD COLUMN IF NOT EXISTS "SecurityContactHash" character varying(71) NULL;
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_domain_certificates (
                "CertificateId" character varying(128) NOT NULL,
                "EnrollmentId" character varying(128) NOT NULL,
                "OwnerId" character varying(256) NOT NULL,
                "Domain" character varying(253) NOT NULL,
                "Level" character varying(32) NOT NULL,
                "Status" character varying(64) NOT NULL,
                "PolicyVersion" character varying(128) NOT NULL,
                "CertificateVersion" integer NOT NULL,
                "IsCurrent" boolean NOT NULL,
                "IssuedAtUtc" timestamp with time zone NULL,
                "ExpiresAtUtc" timestamp with time zone NULL,
                "LastVerificationAtUtc" timestamp with time zone NULL,
                "LastMonitoringAtUtc" timestamp with time zone NULL,
                "PublicDisplayName" character varying(200) NULL,
                "PublicOrganizationName" character varying(200) NULL,
                "SigningKeyId" character varying(128) NULL,
                "SignatureAlgorithm" character varying(128) NULL,
                "CanonicalPayload" text NULL,
                "Signature" text NULL,
                "VerificationMethodsJson" text NULL,
                "PublicFindingsSummaryJson" text NULL,
                "PublicRiskClassification" character varying(80) NULL,
                "PublicCertificateUrl" character varying(512) NULL,
                "RevocationStatusUrl" character varying(512) NULL,
                "AggregateVersion" bigint NOT NULL,
                "CertificateDigest" character varying(71) NULL,
                "RegistrantPublicKeyId" character varying(128) NULL,
                "SignatureAlgorithmFamily" character varying(80) NULL,
                "SignatureCanonicalization" character varying(80) NULL,
                "SignedCertificateJson" text NULL,
                "SigningAuthorityId" character varying(256) NULL,
                "SourceDecisionDigest" character varying(71) NULL,
                CONSTRAINT "PK_hip_domain_certificates" PRIMARY KEY ("CertificateId"),
                CONSTRAINT "FK_hip_domain_certificates_hip_domain_enrollments"
                    FOREIGN KEY ("EnrollmentId") REFERENCES hip_domain_enrollments ("EnrollmentId")
                    ON DELETE RESTRICT
            );
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            ALTER TABLE hip_domain_certificates
                ADD COLUMN IF NOT EXISTS "CertificateDigest" character varying(71) NULL,
                ADD COLUMN IF NOT EXISTS "RegistrantPublicKeyId" character varying(128) NULL,
                ADD COLUMN IF NOT EXISTS "SignatureAlgorithmFamily" character varying(80) NULL,
                ADD COLUMN IF NOT EXISTS "SignatureCanonicalization" character varying(80) NULL,
                ADD COLUMN IF NOT EXISTS "SignedCertificateJson" text NULL,
                ADD COLUMN IF NOT EXISTS "SigningAuthorityId" character varying(256) NULL,
                ADD COLUMN IF NOT EXISTS "SourceDecisionDigest" character varying(71) NULL;
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE TABLE IF NOT EXISTS hip_domain_certificate_events (
                "EventId" character varying(128) NOT NULL,
                "EnrollmentId" character varying(128) NOT NULL,
                "CertificateId" character varying(128) NULL,
                "EventType" character varying(80) NOT NULL,
                "PreviousStatus" character varying(64) NULL,
                "CurrentStatus" character varying(64) NOT NULL,
                "ActorId" character varying(256) NOT NULL,
                "ReasonCode" character varying(120) NULL,
                "PublicSummary" character varying(500) NULL,
                "PolicyVersion" character varying(128) NOT NULL,
                "EvidenceDigest" character varying(71) NULL,
                "OccurredAtUtc" timestamp with time zone NOT NULL,
                CONSTRAINT "PK_hip_domain_certificate_events" PRIMARY KEY ("EventId"),
                CONSTRAINT "FK_hip_domain_certificate_events_hip_domain_enrollments"
                    FOREIGN KEY ("EnrollmentId") REFERENCES hip_domain_enrollments ("EnrollmentId")
                    ON DELETE RESTRICT,
                CONSTRAINT "FK_hip_domain_certificate_events_hip_domain_certificates"
                    FOREIGN KEY ("CertificateId") REFERENCES hip_domain_certificates ("CertificateId")
                    ON DELETE RESTRICT
            );
            """,
            cancellationToken);

        await dbContext.Database.ExecuteSqlRawAsync(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS "IX_hip_domain_enrollments_Domain"
            ON hip_domain_enrollments ("Domain")
            WHERE "IsCurrent" = TRUE;
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_enrollments_OwnerId"
            ON hip_domain_enrollments ("OwnerId");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_enrollments_Status"
            ON hip_domain_enrollments ("Status");
            CREATE UNIQUE INDEX IF NOT EXISTS "IX_hip_domain_certificates_Domain"
            ON hip_domain_certificates ("Domain")
            WHERE "IsCurrent" = TRUE;
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificates_EnrollmentId"
            ON hip_domain_certificates ("EnrollmentId");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificates_ExpiresAtUtc"
            ON hip_domain_certificates ("ExpiresAtUtc");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificates_OwnerId"
            ON hip_domain_certificates ("OwnerId");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificates_Status"
            ON hip_domain_certificates ("Status");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificate_events_CertificateId_OccurredAtUtc"
            ON hip_domain_certificate_events ("CertificateId", "OccurredAtUtc");
            CREATE INDEX IF NOT EXISTS "IX_hip_domain_certificate_events_EnrollmentId_OccurredAtUtc"
            ON hip_domain_certificate_events ("EnrollmentId", "OccurredAtUtc");
            """,
            cancellationToken);
    }
}
