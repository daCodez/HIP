using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Domain.Audit;

namespace HIP.Application.Review;

public static class AuditLogIntegrity
{
    public const string CurrentVersion = "sha256-v1";

    public static AuditLogEntry Seal(AuditLogEntry entry) => entry with
    {
        IntegrityVersion = CurrentVersion,
        IntegrityHash = Compute(entry)
    };

    public static bool Verify(AuditLogEntry entry) =>
        string.IsNullOrWhiteSpace(entry.IntegrityVersion) && string.IsNullOrWhiteSpace(entry.IntegrityHash) ||
        entry.IntegrityVersion == CurrentVersion &&
        !string.IsNullOrWhiteSpace(entry.IntegrityHash) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(entry.IntegrityHash),
            Encoding.ASCII.GetBytes(Compute(entry)));

    public static string Compute(AuditLogEntry entry)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            entry.AuditLogId,
            entry.ActorId,
            entry.ActorRole,
            entry.Action,
            TargetType = entry.TargetType.ToString(),
            entry.TargetId,
            entry.Summary,
            CreatedAtUtc = entry.CreatedAtUtc.ToUniversalTime().ToString("O"),
            Severity = entry.Severity.ToString(),
            Metadata = Ordered(entry.Metadata),
            BeforeMetadata = Ordered(entry.BeforeMetadata),
            AfterMetadata = Ordered(entry.AfterMetadata),
            entry.CorrelationId
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static SortedDictionary<string, string> Ordered(IReadOnlyDictionary<string, string> values)
    {
        var ordered = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in values)
        {
            ordered[pair.Key] = pair.Value;
        }

        return ordered;
    }
}

public sealed record AuditExportPackage(byte[] JsonLines, string Sha256, int EntryCount, DateTimeOffset? EarliestAtUtc, DateTimeOffset? LatestAtUtc);

public interface IAuditExportService
{
    Task<AuditExportPackage> ExportAsync(CancellationToken cancellationToken);
}

public sealed class AuditExportService(IAuditLogService auditLogService) : IAuditExportService
{
    public async Task<AuditExportPackage> ExportAsync(CancellationToken cancellationToken)
    {
        var entries = (await auditLogService.ListAsync(cancellationToken))
            .OrderBy(entry => entry.CreatedAtUtc)
            .ThenBy(entry => entry.AuditLogId, StringComparer.Ordinal)
            .ToArray();
        using var output = new MemoryStream();
        foreach (var entry in entries)
        {
            await JsonSerializer.SerializeAsync(output, entry, cancellationToken: cancellationToken);
            output.WriteByte((byte)'\n');
        }

        var bytes = output.ToArray();
        return new AuditExportPackage(
            bytes,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            entries.Length,
            entries.FirstOrDefault()?.CreatedAtUtc,
            entries.LastOrDefault()?.CreatedAtUtc);
    }
}
