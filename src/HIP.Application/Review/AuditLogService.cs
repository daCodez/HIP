using System.Security.Cryptography;
using System.Text;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class AuditLogService(IAuditLogRepository repository) : IAuditLogService
{
    /// <inheritdoc />
    public AuditLogEntry CreateEntry(
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null)
    {
        var entry = new AuditLogEntry(
            $"audit-{Guid.NewGuid():N}",
            string.IsNullOrWhiteSpace(actorId) ? "system" : actorId,
            action,
            targetType,
            targetId,
            Sanitize(summary),
            DateTimeOffset.UtcNow,
            Sanitize(metadata),
            severity)
        {
            ActorRole = string.IsNullOrWhiteSpace(actorRole) ? "Unknown" : actorRole,
            BeforeMetadata = Sanitize(beforeMetadata),
            AfterMetadata = Sanitize(afterMetadata),
            CorrelationId = correlationId
        };
        return AuditLogIntegrity.Seal(entry);
    }

    public AuditLogEntry Write(
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null)
    {
        var entry = CreateEntry(
            actorId,
            action,
            targetType,
            targetId,
            summary,
            severity,
            metadata,
            actorRole,
            beforeMetadata,
            afterMetadata,
            correlationId);

        Run(repository.SaveAsync(entry, CancellationToken.None));
        return entry;
    }

    /// <inheritdoc />
    public async Task<AuditLogEntry> WriteAsync(
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null)
    {
        var entry = CreateEntry(
            actorId,
            action,
            targetType,
            targetId,
            summary,
            severity,
            metadata,
            actorRole,
            beforeMetadata,
            afterMetadata,
            correlationId);
        await repository.SaveAsync(entry, cancellationToken).ConfigureAwait(false);
        return entry;
    }

    public AuditLogEntry WriteOnce(
        string idempotencyKey,
        string actorId,
        string action,
        TargetType targetType,
        string targetId,
        string summary,
        AuditSeverity severity,
        IReadOnlyDictionary<string, string>? metadata = null,
        string? actorRole = null,
        IReadOnlyDictionary<string, string>? beforeMetadata = null,
        IReadOnlyDictionary<string, string>? afterMetadata = null,
        string? correlationId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(idempotencyKey);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(idempotencyKey)))
            .ToLowerInvariant();
        var entry = AuditLogIntegrity.Seal(CreateEntry(
            actorId,
            action,
            targetType,
            targetId,
            summary,
            severity,
            metadata,
            actorRole,
            beforeMetadata,
            afterMetadata,
            correlationId) with
        {
            AuditLogId = $"audit-idempotent-{hash}"
        });
        Run(repository.TryCreateAsync(entry, CancellationToken.None));
        return entry;
    }

    public IReadOnlyCollection<AuditLogEntry> List() =>
        Run(ListAsync(CancellationToken.None));

    public async Task<IReadOnlyCollection<AuditLogEntry>> ListAsync(CancellationToken cancellationToken)
    {
        var entries = await repository.ListAsync(cancellationToken).ConfigureAwait(false);
        var invalid = entries.Where(entry => !AuditLogIntegrity.Verify(entry)).ToArray();
        foreach (var entry in invalid)
        {
            if (!IsKnownDeviceTimestampSealDefect(entry))
            {
                throw new InvalidOperationException("HIP audit integrity verification failed.");
            }

            var repaired = AuditLogIntegrity.Seal(entry);
            var attestation = CreateRepairAttestation(entry);
            _ = await repository.TryRepairKnownIntegrityDefectAsync(
                    entry,
                    repaired,
                    attestation,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (invalid.Length > 0)
        {
            entries = await repository.ListAsync(cancellationToken).ConfigureAwait(false);
            if (entries.Any(entry => !AuditLogIntegrity.Verify(entry)))
            {
                throw new InvalidOperationException("HIP audit integrity verification failed.");
            }
        }

        return entries
            .OrderByDescending(entry => entry.CreatedAtUtc)
            .ToArray();
    }

    private AuditLogEntry CreateRepairAttestation(AuditLogEntry repairedEntry)
    {
        var material = Encoding.UTF8.GetBytes($"audit-integrity-repair\n{repairedEntry.AuditLogId}");
        var repairId = $"audit-idempotent-{Convert.ToHexString(SHA256.HashData(material)).ToLowerInvariant()}";
        return AuditLogIntegrity.Seal(CreateEntry(
            "system",
            "AuditIntegrity.LegacyDeviceTimestampResealed",
            TargetType.DeviceKey,
            repairedEntry.TargetId,
            "HIP resealed integrity metadata affected by a known device-audit timestamp defect.",
            AuditSeverity.Medium,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["defectVersion"] = "device-created-at-post-seal-v1",
                ["repairedAuditLogId"] = repairedEntry.AuditLogId
            },
            actorRole: "System") with
        {
            AuditLogId = repairId
        });
    }

    private static bool IsKnownDeviceTimestampSealDefect(AuditLogEntry entry)
    {
        if (entry.IntegrityVersion != AuditLogIntegrity.CurrentVersion ||
            entry.IntegrityHash is null || !IsLowerHex(entry.IntegrityHash, 64) ||
            !entry.AuditLogId.StartsWith("audit-", StringComparison.Ordinal) ||
            !entry.ActorId.StartsWith("owner-hmac-sha256-v1:", StringComparison.Ordinal) ||
            !IsLowerHex(entry.ActorId["owner-hmac-sha256-v1:".Length..], 64) ||
            entry.ActorRole != "Consumer" || entry.TargetType != TargetType.DeviceKey ||
            string.IsNullOrWhiteSpace(entry.TargetId) || entry.TargetId.Length > 128 ||
            entry.CreatedAtUtc.Offset != TimeSpan.Zero || entry.BeforeMetadata.Count != 0 ||
            entry.AfterMetadata.Count != 0 || entry.CorrelationId is not null)
        {
            return false;
        }

        var expectedKeys = entry.Action switch
        {
            "ConsumerDevice.RegistrationChallengeIssued" when
                entry.Severity == AuditSeverity.Low &&
                entry.Summary == "A short-lived consumer device registration challenge was issued." =>
                new[] { "expiresAtUtc", "keyAlgorithm", "platformType", "publicKeyFingerprint" },
            "ConsumerDevice.Registered" when
                entry.Severity == AuditSeverity.Medium &&
                entry.Summary == "A consumer device completed proof-of-possession registration." =>
                new[] { "keyAlgorithm", "publicKeyFingerprint", "revocationState", "trustState" },
            "ConsumerDevice.Revoked" when
                entry.Severity == AuditSeverity.High &&
                entry.Summary == "A consumer device was irreversibly revoked." =>
                new[] { "keyAlgorithm", "publicKeyFingerprint", "revocationState", "trustState" },
            _ => null
        };
        return expectedKeys is not null &&
               entry.Metadata.Keys.Order(StringComparer.Ordinal).SequenceEqual(expectedKeys) &&
               entry.Metadata.Values.All(value => !string.IsNullOrWhiteSpace(value) && value.Length <= 256);
    }

    private static bool IsLowerHex(string value, int length) =>
        value.Length == length && value.AsSpan().IndexOfAnyExcept("0123456789abcdef") < 0;

    private static IReadOnlyDictionary<string, string> Sanitize(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null)
        {
            return new Dictionary<string, string>();
        }

        return metadata
            .Where(pair => !IsPrivateContentKey(pair.Key))
            .ToDictionary(pair => pair.Key, pair => Sanitize(pair.Value), StringComparer.OrdinalIgnoreCase);
    }

    private static string Sanitize(string value) =>
        ContainsPrivateContentMarker(value) ? "[privacy-safe summary redacted]" : value;

    private static bool IsPrivateContentKey(string key) =>
        key.Contains("privateChat", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("chatLog", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("messageBody", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("rawPrivate", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsPrivateContentMarker(string value) =>
        value.Contains("private chat content", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("raw private message", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("privateChatLog", StringComparison.OrdinalIgnoreCase);

    private static void Run(Task task) =>
        task.GetAwaiter().GetResult();

    private static T Run<T>(Task<T> task) =>
        task.GetAwaiter().GetResult();
}
