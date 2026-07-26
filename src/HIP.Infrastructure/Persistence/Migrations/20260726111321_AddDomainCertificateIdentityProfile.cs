using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainCertificateIdentityProfile : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PublicCountryOrRegion",
                table: "hip_domain_enrollments",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PublicDisplayName",
                table: "hip_domain_enrollments",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PublicOrganizationName",
                table: "hip_domain_enrollments",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PublicWebsiteContact",
                table: "hip_domain_enrollments",
                type: "character varying(320)",
                maxLength: 320,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SecurityContactHash",
                table: "hip_domain_enrollments",
                type: "character varying(71)",
                maxLength: 71,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PublicCountryOrRegion",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "PublicDisplayName",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "PublicOrganizationName",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "PublicWebsiteContact",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "SecurityContactHash",
                table: "hip_domain_enrollments");
        }
    }
}
