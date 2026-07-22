using System.Net;
using System.Security.Cryptography;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Api;

/// <summary>Verifies the authorized, tamper-evident HIP audit export API contract.</summary>
public sealed class AdminAuditExportApiTests
{
    /// <summary>Proves an authorized admin receives NDJSON whose advertised checksum is exact.</summary>
    [Test]
    public async Task Authorized_export_is_no_store_and_checksum_verifiable()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using (var scope = factory.Services.CreateScope())
        {
            var auditLogService = scope.ServiceProvider.GetRequiredService<IAuditLogService>();
            auditLogService.Write(
                "audit-export-test",
                "ExportableAction",
                TargetType.Rule,
                "rule-export-test",
                "Export-safe audit entry.",
                AuditSeverity.Low);
        }

        using var client = factory.CreateClient();
        AddAdmin(client);
        using var response = await client.GetAsync("/api/v1/admin/audit/export");
        var bytes = await response.Content.ReadAsByteArrayAsync();
        var expectedChecksum = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var advertisedChecksum = response.Headers.GetValues("X-HIP-Audit-Sha256").Single();
        var advertisedCount = int.Parse(
            response.Headers.GetValues("X-HIP-Audit-Entry-Count").Single(),
            System.Globalization.CultureInfo.InvariantCulture);

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/x-ndjson"));
            Assert.That(response.Headers.CacheControl?.NoStore, Is.True);
            Assert.That(advertisedChecksum, Is.EqualTo(expectedChecksum));
            Assert.That(advertisedCount, Is.GreaterThanOrEqualTo(1));
            Assert.That(response.Content.Headers.ContentDisposition?.FileNameStar, Is.EqualTo("hip-audit-export.jsonl"));
        });
    }

    /// <summary>Proves audit export is unavailable without an authenticated admin identity.</summary>
    [Test]
    public async Task Anonymous_export_is_rejected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/v1/admin/audit/export");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static void AddAdmin(HttpClient client)
    {
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Admin");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "admin-audit-export-test");
    }
}
