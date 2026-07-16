using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialHipSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "hip_browser_scan_results",
                columns: table => new
                {
                    ScanResultId = table.Column<string>(type: "character varying(220)", maxLength: 220, nullable: false),
                    Domain = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: false),
                    PageUrlHash = table.Column<string>(type: "character varying(96)", maxLength: 96, nullable: false),
                    StoredPageUrl = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    ScanSource = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    Score = table.Column<int>(type: "integer", nullable: false),
                    RiskLevel = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    Status = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    ReasonsJson = table.Column<string>(type: "text", nullable: false),
                    LinksScanned = table.Column<int>(type: "integer", nullable: false),
                    RiskyLinksFound = table.Column<int>(type: "integer", nullable: false),
                    SuspiciousLinksFound = table.Column<int>(type: "integer", nullable: false),
                    DangerousLinksFound = table.Column<int>(type: "integer", nullable: false),
                    LastCheckedUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RecommendedAction = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                    PrivacySafeMetadataJson = table.Column<string>(type: "text", nullable: false),
                    PluginVersion = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_browser_scan_results", x => x.ScanResultId);
                });

            migrationBuilder.CreateTable(
                name: "hip_dashboard_scan_aggregates",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                    TotalScans = table.Column<int>(type: "integer", nullable: false),
                    ScansToday = table.Column<int>(type: "integer", nullable: false),
                    Trusted = table.Column<int>(type: "integer", nullable: false),
                    MostlyTrusted = table.Column<int>(type: "integer", nullable: false),
                    LimitedTrustData = table.Column<int>(type: "integer", nullable: false),
                    Unknown = table.Column<int>(type: "integer", nullable: false),
                    Suspicious = table.Column<int>(type: "integer", nullable: false),
                    HighRisk = table.Column<int>(type: "integer", nullable: false),
                    Dangerous = table.Column<int>(type: "integer", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_dashboard_scan_aggregates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "hip_records",
                columns: table => new
                {
                    Partition = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                    Id = table.Column<string>(type: "character varying(220)", maxLength: 220, nullable: false),
                    Json = table.Column<string>(type: "text", nullable: false),
                    CreatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_records", x => new { x.Partition, x.Id });
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_browser_scan_results_Domain",
                table: "hip_browser_scan_results",
                column: "Domain");

            migrationBuilder.CreateIndex(
                name: "IX_hip_browser_scan_results_Domain_LastCheckedUtc",
                table: "hip_browser_scan_results",
                columns: new[] { "Domain", "LastCheckedUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_hip_browser_scan_results_LastCheckedUtc",
                table: "hip_browser_scan_results",
                column: "LastCheckedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_hip_browser_scan_results_RiskLevel",
                table: "hip_browser_scan_results",
                column: "RiskLevel");

            migrationBuilder.CreateIndex(
                name: "IX_hip_browser_scan_results_Status",
                table: "hip_browser_scan_results",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_hip_dashboard_scan_aggregates_UpdatedAtUtc",
                table: "hip_dashboard_scan_aggregates",
                column: "UpdatedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_hip_records_UpdatedAtUtc",
                table: "hip_records",
                column: "UpdatedAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_browser_scan_results");

            migrationBuilder.DropTable(
                name: "hip_dashboard_scan_aggregates");

            migrationBuilder.DropTable(
                name: "hip_records");
        }
    }
}
