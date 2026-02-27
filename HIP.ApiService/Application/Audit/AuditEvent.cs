namespace HIP.ApiService.Application.Audit;

public sealed record AuditEvent(
    string Id,
    DateTimeOffset CreatedAtUtc,
    string EventType,
    string Subject,
    string Source,
    string Detail);
