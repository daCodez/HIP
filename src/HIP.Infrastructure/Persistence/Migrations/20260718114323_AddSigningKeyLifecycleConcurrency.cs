using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddSigningKeyLifecycleConcurrency : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "AggregateVersion",
                table: "hip_records",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AggregateVersion",
                table: "hip_records");
        }
    }
}
