namespace HIP.Audit.Models;

/// <summary>
/// Filter options for reading audit events.
/// </summary>
public sealed record AuditQuery(
    int Take = 50,
    string? EventType = null,
    string? IdentityId = null,
    string? Outcome = null,
    string? ReasonCode = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null);
