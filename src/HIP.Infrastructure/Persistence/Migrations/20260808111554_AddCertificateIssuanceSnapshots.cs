using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateIssuanceSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ApplicationId",
                table: "hip_domain_certificates",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ManagedDomainId",
                table: "hip_domain_certificates",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OrganizationId",
                table: "hip_domain_certificates",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PublicCertificateNumber",
                table: "hip_domain_certificates",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "hip_domain_certificate_snapshots",
                columns: table => new
                {
                    CertificateId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    HipScore = table.Column<int>(type: "integer", nullable: false),
                    DomainTrustScore = table.Column<int>(type: "integer", nullable: true),
                    PageTrustScore = table.Column<int>(type: "integer", nullable: true),
                    ContentRiskScore = table.Column<int>(type: "integer", nullable: true),
                    RelevantSecurityStatus = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    HttpsAvailable = table.Column<bool>(type: "boolean", nullable: false),
                    DnssecStatus = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ScanId = table.Column<string>(type: "character varying(220)", maxLength: 220, nullable: true),
                    RuleVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    PolicyVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EvaluatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_domain_certificate_snapshots", x => x.CertificateId);
                    table.ForeignKey(
                        name: "FK_hip_domain_certificate_snapshots_hip_domain_certificates_Ce~",
                        column: x => x.CertificateId,
                        principalTable: "hip_domain_certificates",
                        principalColumn: "CertificateId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_ApplicationId",
                table: "hip_domain_certificates",
                column: "ApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_ManagedDomainId",
                table: "hip_domain_certificates",
                column: "ManagedDomainId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificates_PublicCertificateNumber",
                table: "hip_domain_certificates",
                column: "PublicCertificateNumber",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_certificate_snapshots_ScanId",
                table: "hip_domain_certificate_snapshots",
                column: "ScanId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_domain_certificate_snapshots");

            migrationBuilder.DropIndex(
                name: "IX_hip_domain_certificates_ApplicationId",
                table: "hip_domain_certificates");

            migrationBuilder.DropIndex(
                name: "IX_hip_domain_certificates_ManagedDomainId",
                table: "hip_domain_certificates");

            migrationBuilder.DropIndex(
                name: "IX_hip_domain_certificates_PublicCertificateNumber",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "ApplicationId",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "ManagedDomainId",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "OrganizationId",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "PublicCertificateNumber",
                table: "hip_domain_certificates");
        }
    }
}
