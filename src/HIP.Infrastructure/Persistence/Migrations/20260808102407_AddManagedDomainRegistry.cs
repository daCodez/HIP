using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddManagedDomainRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "hip_domain_organizations",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_domain_organizations", x => x.OrganizationId);
                });

            migrationBuilder.CreateTable(
                name: "hip_managed_domains",
                columns: table => new
                {
                    DomainId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DomainName = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    OwnerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    OrganizationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DnssecStatus = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    DnssecDiagnostic = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_managed_domains", x => x.DomainId);
                    table.ForeignKey(
                        name: "FK_hip_managed_domains_hip_domain_organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "hip_domain_organizations",
                        principalColumn: "OrganizationId",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "hip_organization_memberships",
                columns: table => new
                {
                    OrganizationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UserId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_organization_memberships", x => new { x.OrganizationId, x.UserId });
                    table.ForeignKey(
                        name: "FK_hip_organization_memberships_hip_domain_organizations_Organ~",
                        column: x => x.OrganizationId,
                        principalTable: "hip_domain_organizations",
                        principalColumn: "OrganizationId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "hip_managed_domain_access",
                columns: table => new
                {
                    DomainId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UserId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_managed_domain_access", x => new { x.DomainId, x.UserId });
                    table.ForeignKey(
                        name: "FK_hip_managed_domain_access_hip_managed_domains_DomainId",
                        column: x => x.DomainId,
                        principalTable: "hip_managed_domains",
                        principalColumn: "DomainId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_organizations_Name",
                table: "hip_domain_organizations",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domain_access_UserId",
                table: "hip_managed_domain_access",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domains_DomainName",
                table: "hip_managed_domains",
                column: "DomainName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domains_OrganizationId",
                table: "hip_managed_domains",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domains_OwnerId",
                table: "hip_managed_domains",
                column: "OwnerId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domains_Status",
                table: "hip_managed_domains",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_hip_organization_memberships_UserId",
                table: "hip_organization_memberships",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_managed_domain_access");

            migrationBuilder.DropTable(
                name: "hip_organization_memberships");

            migrationBuilder.DropTable(
                name: "hip_managed_domains");

            migrationBuilder.DropTable(
                name: "hip_domain_organizations");
        }
    }
}
