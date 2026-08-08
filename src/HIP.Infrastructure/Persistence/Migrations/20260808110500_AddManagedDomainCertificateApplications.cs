using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddManagedDomainCertificateApplications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "hip_managed_domain_certificate_applications",
                columns: table => new
                {
                    ApplicationId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DomainId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DomainName = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    RequestedLevel = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ApplicantId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    OrganizationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    SubmittedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    EligibilityJson = table.Column<string>(type: "text", nullable: true),
                    SecurityFindingsJson = table.Column<string>(type: "text", nullable: false),
                    RequiredRemediationJson = table.Column<string>(type: "text", nullable: false),
                    ReviewerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ReviewerNotes = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Decision = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    DecisionAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_managed_domain_certificate_applications", x => x.ApplicationId);
                    table.ForeignKey(
                        name: "FK_hip_managed_domain_certificate_applications_hip_managed_dom~",
                        column: x => x.DomainId,
                        principalTable: "hip_managed_domains",
                        principalColumn: "DomainId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domain_certificate_applications_DomainId_Create~",
                table: "hip_managed_domain_certificate_applications",
                columns: new[] { "DomainId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domain_certificate_applications_Status",
                table: "hip_managed_domain_certificate_applications",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_managed_domain_certificate_applications");
        }
    }
}
