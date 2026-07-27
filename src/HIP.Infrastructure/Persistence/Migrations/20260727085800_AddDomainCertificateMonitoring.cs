using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDomainCertificateMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "MonitoringEnabledAtUtc",
                table: "hip_domain_enrollments",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "MonitoringFailureCount",
                table: "hip_domain_enrollments",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "MonitoringNextCheckAtUtc",
                table: "hip_domain_enrollments",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_hip_domain_enrollments_monitoring_due",
                table: "hip_domain_enrollments",
                columns: new[] { "MonitoringEnabledAtUtc", "MonitoringNextCheckAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_hip_domain_enrollments_monitoring_due",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "MonitoringEnabledAtUtc",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "MonitoringFailureCount",
                table: "hip_domain_enrollments");

            migrationBuilder.DropColumn(
                name: "MonitoringNextCheckAtUtc",
                table: "hip_domain_enrollments");
        }
    }
}
