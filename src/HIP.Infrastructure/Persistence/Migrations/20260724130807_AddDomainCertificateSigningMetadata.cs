using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainCertificateSigningMetadata : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CertificateDigest",
                table: "hip_domain_certificates",
                type: "character varying(71)",
                maxLength: 71,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RegistrantPublicKeyId",
                table: "hip_domain_certificates",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureAlgorithmFamily",
                table: "hip_domain_certificates",
                type: "character varying(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignatureCanonicalization",
                table: "hip_domain_certificates",
                type: "character varying(80)",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignedCertificateJson",
                table: "hip_domain_certificates",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SigningAuthorityId",
                table: "hip_domain_certificates",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SourceDecisionDigest",
                table: "hip_domain_certificates",
                type: "character varying(71)",
                maxLength: 71,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CertificateDigest",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "RegistrantPublicKeyId",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "SignatureAlgorithmFamily",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "SignatureCanonicalization",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "SignedCertificateJson",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "SigningAuthorityId",
                table: "hip_domain_certificates");

            migrationBuilder.DropColumn(
                name: "SourceDecisionDigest",
                table: "hip_domain_certificates");
        }
    }
}
