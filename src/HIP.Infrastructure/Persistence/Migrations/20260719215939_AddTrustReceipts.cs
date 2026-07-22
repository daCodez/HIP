using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace HIP.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTrustReceipts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "hip_trust_receipts",
                columns: table => new
                {
                    ReceiptId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RelatedEvaluationId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ReceiptJson = table.Column<string>(type: "text", nullable: false),
                    ReceiptDigest = table.Column<string>(type: "character varying(71)", maxLength: 71, nullable: false),
                    SourceEvaluationDigest = table.Column<string>(type: "character varying(71)", maxLength: 71, nullable: false),
                    DocumentType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProtocolVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SubjectType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    SubjectId = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    EvaluatedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IssuedAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresAtUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PolicyVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    RuleSetVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    EvidenceDigest = table.Column<string>(type: "character varying(71)", maxLength: 71, nullable: false),
                    IssuerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    KeyId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hip_trust_receipts", x => x.ReceiptId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_hip_trust_receipts_ExpiresAtUtc",
                table: "hip_trust_receipts",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_hip_trust_receipts_IssuerId",
                table: "hip_trust_receipts",
                column: "IssuerId");

            migrationBuilder.CreateIndex(
                name: "IX_hip_trust_receipts_RelatedEvaluationId",
                table: "hip_trust_receipts",
                column: "RelatedEvaluationId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_hip_trust_receipts_SubjectId",
                table: "hip_trust_receipts",
                column: "SubjectId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "hip_trust_receipts");
        }
    }
}
