namespace HIP.ApiService.Infrastructure.Persistence;

/// <summary>
/// Durable audit event row for security and policy observability.
/// </summary>
public sealed class AuditEventRecord
{
    /// <summary>Unique audit event identifier.</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the event was emitted.</summary>
    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>Machine-readable event type.</summary>
    public string EventType { get; set; } = string.Empty;

    /// <summary>Primary identity/subject associated with the event.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Source subsystem for the event.</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>Sanitized detail text.</summary>
    public string Detail { get; set; } = string.Empty;

    /// <summary>Optional event category (security/policy/api/token).</summary>
    public string? Category { get; set; }

    /// <summary>Optional normalized outcome label.</summary>
    public string? Outcome { get; set; }

    /// <summary>Optional machine-readable reason code.</summary>
    public string? ReasonCode { get; set; }

    /// <summary>Optional route pattern.</summary>
    public string? Route { get; set; }

    /// <summary>Optional request correlation id / trace id.</summary>
    public string? CorrelationId { get; set; }

    /// <summary>Optional request latency in milliseconds.</summary>
    public double? LatencyMs { get; set; }
}
