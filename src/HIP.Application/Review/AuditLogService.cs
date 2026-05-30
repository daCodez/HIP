using System.Collections.Concurrent;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

public sealed class AuditLogService : IAuditLogService
{
    private readonly ConcurrentDictionary<string, AuditLogEntry> _entries = new();

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

        _entries[entry.AuditLogId] = entry;
        return entry;
    }

    public IReadOnlyCollection<AuditLogEntry> List() =>
        _entries.Values.OrderByDescending(entry => entry.CreatedAtUtc).ToArray();

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
}
