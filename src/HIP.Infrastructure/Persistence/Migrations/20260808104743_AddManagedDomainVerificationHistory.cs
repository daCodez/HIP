using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddManagedDomainVerificationHistory : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "OwnershipVerifiedAtUtc",
                table: "hip_managed_domains",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VerificationMethod",
                table: "hip_managed_domains",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VerificationStatus",
                table: "hip_managed_domains",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "Unverified");

            migrationBuilder.CreateTable(
                name: "hip_managed_domain_verification_events",
                columns: table => new
                {
                    EventId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    DomainId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Method = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    EventType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Outcome = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    TokenDigest = table.Column<string>(type: "character varying(71)", maxLength: 71, nullable: false),
                    ChallengeVersion = table.Column<int>(type: "integer", nullable: false),
                    OccurredAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ChallengeExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_managed_domain_verification_events", x => x.EventId);
                    table.ForeignKey(
                        name: "FK_hip_managed_domain_verification_events_hip_managed_domains_~",
                        column: x => x.DomainId,
                        principalTable: "hip_managed_domains",
                        principalColumn: "DomainId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_managed_domain_verification_events_DomainId_OccurredAtU~",
                table: "hip_managed_domain_verification_events",
                columns: new[] { "DomainId", "OccurredAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_managed_domain_verification_events");

            migrationBuilder.DropColumn(
                name: "OwnershipVerifiedAtUtc",
                table: "hip_managed_domains");

            migrationBuilder.DropColumn(
                name: "VerificationMethod",
                table: "hip_managed_domains");

            migrationBuilder.DropColumn(
                name: "VerificationStatus",
                table: "hip_managed_domains");
        }
    }
}
