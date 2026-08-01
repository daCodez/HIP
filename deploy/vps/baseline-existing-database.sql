BEGIN;

DO $baseline$
BEGIN
    IF to_regclass('public."__EFMigrationsHistory"') IS NOT NULL THEN
        RAISE EXCEPTION '__EFMigrationsHistory already exists; refusing to baseline';
    END IF;
END
$baseline$;

CREATE TABLE "__EFMigrationsHistory" (
    "MigrationId" character varying(150) NOT NULL,
    "ProductVersion" character varying(32) NOT NULL,
    CONSTRAINT "PK___EFMigrationsHistory" PRIMARY KEY ("MigrationId")
);

INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
VALUES
    ('20260716183123_InitialHipSchema', '10.0.4'),
    ('20260718114323_AddSigningKeyLifecycleConcurrency', '10.0.4'),
    ('20260719215939_AddTrustReceipts', '10.0.4'),
    ('20260724110331_AddDomainTrustCertificates', '10.0.4'),
    ('20260724130807_AddDomainCertificateSigningMetadata', '10.0.4'),
    ('20260726111321_AddDomainCertificateIdentityProfile', '10.0.4'),
    ('20260726151934_AddDomainCertificateApplications', '10.0.4'),
    ('20260727085800_AddDomainCertificateMonitoring', '10.0.4');

DO $baseline$
BEGIN
    IF (SELECT count(*) FROM "__EFMigrationsHistory") <> 8 THEN
        RAISE EXCEPTION 'migration baseline row count is not 8';
    END IF;
END
$baseline$;

COMMIT;
