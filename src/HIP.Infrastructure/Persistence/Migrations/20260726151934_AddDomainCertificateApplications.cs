using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainCertificateApplications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ApplicantAttestationDigest",
                table: "hip_domain_enrollments",
                type: "character varying(71)",
                maxLength: 71,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ApplicationDecisionReason",
                table: "hip_domain_enrollments",
                type: "character varying(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ApplicationReviewedAtUtc",
                table: "hip_domain_enrollments",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ApplicationStatus",
                table: "hip_domain_enrollments",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Draft");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ApplicationSubmittedAtUtc",
                table: "hip_domain_enrollments",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_enrollments_ApplicationStatus",
                table: "hip_domain_enrollments",
                column: "ApplicationStatus");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_hip_domain_enrollments_ApplicationStatus",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "ApplicantAttestationDigest",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "ApplicationDecisionReason",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "ApplicationReviewedAtUtc",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "ApplicationStatus",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "ApplicationSubmittedAtUtc",
                table: "hip_domain_enrollments");
        }
    }
}
