using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainTrustCertificates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "hip_domain_enrollments",
                columns: table => new
                {
                    EnrollmentId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    OwnerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Domain = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    Status = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PolicyVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    IsCurrent = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DnsVerifiedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    WebsiteVerifiedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    IdentityCompletedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SecurityReviewCompletedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastMonitoringAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CurrentScore = table.Column<int>(type: "integer", nullable: true),
                    UnresolvedCriticalFindings = table.Column<int>(type: "integer", nullable: false),
                    AggregateVersion = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_domain_enrollments", x => x.EnrollmentId);
                });

            migrationBuilder.CreateTable(
                name: "hip_domain_certificates",
                columns: table => new
                {
                    CertificateId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EnrollmentId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    OwnerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Domain = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    Level = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    PolicyVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CertificateVersion = table.Column<int>(type: "integer", nullable: false),
                    IsCurrent = table.Column<bool>(type: "boolean", nullable: false),
                    IssuedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastVerificationAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastMonitoringAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    PublicDisplayName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    PublicOrganizationName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    SigningKeyId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    SignatureAlgorithm = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    CanonicalPayload = table.Column<string>(type: "text", nullable: true),
                    Signature = table.Column<string>(type: "text", nullable: true),
                    VerificationMethodsJson = table.Column<string>(type: "text", nullable: true),
                    PublicFindingsSummaryJson = table.Column<string>(type: "text", nullable: true),
                    PublicRiskClassification = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    PublicCertificateUrl = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    RevocationStatusUrl = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    AggregateVersion = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_domain_certificates", x => x.CertificateId);
                    table.ForeignKey(
                        name: "FK_hip_domain_certificates_hip_domain_enrollments_EnrollmentId",
                        column: x => x.EnrollmentId,
                        principalTable: "hip_domain_enrollments",
                        principalColumn: "EnrollmentId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "hip_domain_certificate_events",
                columns: table => new
                {
                    EventId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EnrollmentId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    CertificateId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    EventType = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    PreviousStatus = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CurrentStatus = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ActorId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ReasonCode = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                    PublicSummary = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    PolicyVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EvidenceDigest = table.Column<string>(type: "character varying(71)", maxLength: 71, nullable: true),
                    OccurredAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_domain_certificate_events", x => x.EventId);
                    table.ForeignKey(
                        name: "FK_hip_domain_certificate_events_hip_domain_certificates_Certi~",
                        column: x => x.CertificateId,
                        principalTable: "hip_domain_certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_hip_domain_certificate_events_hip_domain_enrollments_Enroll~",
                        column: x => x.EnrollmentId,
                        principalTable: "hip_domain_enrollments",
                        principalColumn: "EnrollmentId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificate_events_CertificateId_OccurredAtUtc",
                table: "hip_domain_certificate_events",
                columns: new[] { "CertificateId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificate_events_EnrollmentId_OccurredAtUtc",
                table: "hip_domain_certificate_events",
                columns: new[] { "EnrollmentId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_Domain",
                table: "hip_domain_certificates",
                column: "Domain",
                unique: true,
                filter: "\"IsCurrent\" = TRUE");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_EnrollmentId",
                table: "hip_domain_certificates",
                column: "EnrollmentId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_ExpiresAtUtc",
                table: "hip_domain_certificates",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_OwnerId",
                table: "hip_domain_certificates",
                column: "OwnerId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_Status",
                table: "hip_domain_certificates",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_enrollments_Domain",
                table: "hip_domain_enrollments",
                column: "Domain",
                unique: true,
                filter: "\"IsCurrent\" = TRUE");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_enrollments_OwnerId",
                table: "hip_domain_enrollments",
                column: "OwnerId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_enrollments_Status",
                table: "hip_domain_enrollments",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_domain_certificate_events");

            migrationBuilder.DropTable(
                name: "hip_domain_certificates");

            migrationBuilder.DropTable(
                name: "hip_domain_enrollments");
        }
    }
}
