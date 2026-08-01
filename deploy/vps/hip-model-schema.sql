CREATE TABLE hip_browser_scan_results (
    "ScanResultId" character varying(220) NOT NULL,
    "Domain" character varying(253) NOT NULL,
    "PageUrlHash" character varying(96) NOT NULL,
    "StoredPageUrl" character varying(2048),
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
    "PluginVersion" character varying(80),
    "CreatedAtUtc" timestamp with time zone NOT NULL,
    "UpdatedAtUtc" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_hip_browser_scan_results" PRIMARY KEY ("ScanResultId")
);


CREATE TABLE hip_dashboard_scan_aggregates (
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


CREATE TABLE hip_domain_enrollments (
    "EnrollmentId" character varying(128) NOT NULL,
    "OwnerId" character varying(256) NOT NULL,
    "Domain" character varying(253) NOT NULL,
    "Status" character varying(64) NOT NULL,
    "PolicyVersion" character varying(128) NOT NULL,
    "IsCurrent" boolean NOT NULL,
    "CreatedAtUtc" timestamp with time zone NOT NULL,
    "UpdatedAtUtc" timestamp with time zone NOT NULL,
    "DnsVerifiedAtUtc" timestamp with time zone,
    "WebsiteVerifiedAtUtc" timestamp with time zone,
    "IdentityCompletedAtUtc" timestamp with time zone,
    "PublicDisplayName" character varying(200),
    "PublicOrganizationName" character varying(200),
    "PublicWebsiteContact" character varying(320),
    "PublicCountryOrRegion" character varying(100),
    "SecurityContactHash" character varying(71),
    "ApplicationStatus" character varying(32) NOT NULL DEFAULT 'Draft',
    "ApplicationSubmittedAtUtc" timestamp with time zone,
    "ApplicationReviewedAtUtc" timestamp with time zone,
    "ApplicantAttestationDigest" character varying(71),
    "ApplicationDecisionReason" character varying(500),
    "SecurityReviewCompletedAtUtc" timestamp with time zone,
    "MonitoringEnabledAtUtc" timestamp with time zone,
    "LastMonitoringAtUtc" timestamp with time zone,
    "MonitoringNextCheckAtUtc" timestamp with time zone,
    "MonitoringFailureCount" integer NOT NULL,
    "CurrentScore" integer,
    "UnresolvedCriticalFindings" integer NOT NULL,
    "AggregateVersion" bigint NOT NULL,
    CONSTRAINT "PK_hip_domain_enrollments" PRIMARY KEY ("EnrollmentId")
);


CREATE TABLE hip_records (
    "Partition" character varying(160) NOT NULL,
    "Id" character varying(220) NOT NULL,
    "Json" text NOT NULL,
    "AggregateVersion" bigint NOT NULL DEFAULT 0,
    "CreatedAtUtc" timestamp with time zone NOT NULL,
    "UpdatedAtUtc" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_hip_records" PRIMARY KEY ("Partition", "Id")
);


CREATE TABLE hip_trust_receipts (
    "ReceiptId" character varying(128) NOT NULL,
    "RelatedEvaluationId" character varying(256) NOT NULL,
    "ReceiptJson" text NOT NULL,
    "ReceiptDigest" character varying(71) NOT NULL,
    "SourceEvaluationDigest" character varying(71) NOT NULL,
    "DocumentType" character varying(64) NOT NULL,
    "ProtocolVersion" character varying(32) NOT NULL,
    "SubjectType" character varying(64) NOT NULL,
    "SubjectId" character varying(512) NOT NULL,
    "EvaluatedAtUtc" timestamp with time zone NOT NULL,
    "IssuedAtUtc" timestamp with time zone NOT NULL,
    "ExpiresAtUtc" timestamp with time zone NOT NULL,
    "PolicyVersion" character varying(128) NOT NULL,
    "RuleSetVersion" character varying(128) NOT NULL,
    "EvidenceDigest" character varying(71) NOT NULL,
    "IssuerId" character varying(256) NOT NULL,
    "KeyId" character varying(128) NOT NULL,
    "Algorithm" character varying(128) NOT NULL,
    CONSTRAINT "PK_hip_trust_receipts" PRIMARY KEY ("ReceiptId")
);


CREATE TABLE hip_domain_certificates (
    "CertificateId" character varying(128) NOT NULL,
    "EnrollmentId" character varying(128) NOT NULL,
    "OwnerId" character varying(256) NOT NULL,
    "Domain" character varying(253) NOT NULL,
    "Level" character varying(32) NOT NULL,
    "Status" character varying(64) NOT NULL,
    "PolicyVersion" character varying(128) NOT NULL,
    "CertificateVersion" integer NOT NULL,
    "IsCurrent" boolean NOT NULL,
    "IssuedAtUtc" timestamp with time zone,
    "ExpiresAtUtc" timestamp with time zone,
    "LastVerificationAtUtc" timestamp with time zone,
    "LastMonitoringAtUtc" timestamp with time zone,
    "PublicDisplayName" character varying(200),
    "PublicOrganizationName" character varying(200),
    "SigningKeyId" character varying(128),
    "SignatureAlgorithm" character varying(128),
    "CanonicalPayload" text,
    "Signature" text,
    "SigningAuthorityId" character varying(256),
    "VerificationMethodsJson" text,
    "SignatureAlgorithmFamily" character varying(80),
    "SignatureCanonicalization" character varying(80),
    "RegistrantPublicKeyId" character varying(128),
    "PublicFindingsSummaryJson" text,
    "PublicRiskClassification" character varying(80),
    "PublicCertificateUrl" character varying(512),
    "SignedCertificateJson" text,
    "CertificateDigest" character varying(71),
    "SourceDecisionDigest" character varying(71),
    "RevocationStatusUrl" character varying(512),
    "AggregateVersion" bigint NOT NULL,
    CONSTRAINT "PK_hip_domain_certificates" PRIMARY KEY ("CertificateId"),
    CONSTRAINT "FK_hip_domain_certificates_hip_domain_enrollments_EnrollmentId" FOREIGN KEY ("EnrollmentId") REFERENCES hip_domain_enrollments ("EnrollmentId") ON DELETE RESTRICT
);


CREATE TABLE hip_domain_certificate_events (
    "EventId" character varying(128) NOT NULL,
    "EnrollmentId" character varying(128) NOT NULL,
    "CertificateId" character varying(128),
    "EventType" character varying(80) NOT NULL,
    "PreviousStatus" character varying(64),
    "CurrentStatus" character varying(64) NOT NULL,
    "ActorId" character varying(256) NOT NULL,
    "ReasonCode" character varying(120),
    "PublicSummary" character varying(500),
    "PolicyVersion" character varying(128) NOT NULL,
    "EvidenceDigest" character varying(71),
    "OccurredAtUtc" timestamp with time zone NOT NULL,
    CONSTRAINT "PK_hip_domain_certificate_events" PRIMARY KEY ("EventId"),
    CONSTRAINT "FK_hip_domain_certificate_events_hip_domain_certificates_Certi~" FOREIGN KEY ("CertificateId") REFERENCES hip_domain_certificates ("CertificateId") ON DELETE RESTRICT,
    CONSTRAINT "FK_hip_domain_certificate_events_hip_domain_enrollments_Enroll~" FOREIGN KEY ("EnrollmentId") REFERENCES hip_domain_enrollments ("EnrollmentId") ON DELETE RESTRICT
);


CREATE INDEX "IX_hip_browser_scan_results_Domain" ON hip_browser_scan_results ("Domain");


CREATE INDEX "IX_hip_browser_scan_results_Domain_LastCheckedUtc" ON hip_browser_scan_results ("Domain", "LastCheckedUtc");


CREATE INDEX "IX_hip_browser_scan_results_LastCheckedUtc" ON hip_browser_scan_results ("LastCheckedUtc");


CREATE INDEX "IX_hip_browser_scan_results_RiskLevel" ON hip_browser_scan_results ("RiskLevel");


CREATE INDEX "IX_hip_browser_scan_results_Status" ON hip_browser_scan_results ("Status");


CREATE INDEX "IX_hip_dashboard_scan_aggregates_UpdatedAtUtc" ON hip_dashboard_scan_aggregates ("UpdatedAtUtc");


CREATE INDEX "IX_hip_domain_certificate_events_CertificateId_OccurredAtUtc" ON hip_domain_certificate_events ("CertificateId", "OccurredAtUtc");


CREATE INDEX "IX_hip_domain_certificate_events_EnrollmentId_OccurredAtUtc" ON hip_domain_certificate_events ("EnrollmentId", "OccurredAtUtc");


CREATE UNIQUE INDEX "IX_hip_domain_certificates_Domain" ON hip_domain_certificates ("Domain") WHERE "IsCurrent" = TRUE;


CREATE INDEX "IX_hip_domain_certificates_EnrollmentId" ON hip_domain_certificates ("EnrollmentId");


CREATE INDEX "IX_hip_domain_certificates_ExpiresAtUtc" ON hip_domain_certificates ("ExpiresAtUtc");


CREATE INDEX "IX_hip_domain_certificates_OwnerId" ON hip_domain_certificates ("OwnerId");


CREATE INDEX "IX_hip_domain_certificates_Status" ON hip_domain_certificates ("Status");


CREATE INDEX "IX_hip_domain_enrollments_ApplicationStatus" ON hip_domain_enrollments ("ApplicationStatus");


CREATE UNIQUE INDEX "IX_hip_domain_enrollments_Domain" ON hip_domain_enrollments ("Domain") WHERE "IsCurrent" = TRUE;


CREATE INDEX "IX_hip_domain_enrollments_monitoring_due" ON hip_domain_enrollments ("MonitoringEnabledAtUtc", "MonitoringNextCheckAtUtc");


CREATE INDEX "IX_hip_domain_enrollments_OwnerId" ON hip_domain_enrollments ("OwnerId");


CREATE INDEX "IX_hip_domain_enrollments_Status" ON hip_domain_enrollments ("Status");


CREATE INDEX "IX_hip_records_UpdatedAtUtc" ON hip_records ("UpdatedAtUtc");


CREATE INDEX "IX_hip_trust_receipts_ExpiresAtUtc" ON hip_trust_receipts ("ExpiresAtUtc");


CREATE INDEX "IX_hip_trust_receipts_IssuerId" ON hip_trust_receipts ("IssuerId");


CREATE UNIQUE INDEX "IX_hip_trust_receipts_RelatedEvaluationId" ON hip_trust_receipts ("RelatedEvaluationId");


CREATE INDEX "IX_hip_trust_receipts_SubjectId" ON hip_trust_receipts ("SubjectId");


