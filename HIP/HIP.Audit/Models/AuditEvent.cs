namespace HIP.Audit.Models;

/// <summary>
/// Canonical audit event persisted by HIP audit infrastructure.
/// </summary>
public sealed record AuditEvent(
    string Id,
    DateTimeOffset CreatedAtUtc,
    string EventType,
    string Subject,
    string Source,
    string Detail,
    string? Category = null,
    string? Outcome = null,
    string? ReasonCode = null,
    string? Route = null,
    string? CorrelationId = null,
    double? LatencyMs = null);
