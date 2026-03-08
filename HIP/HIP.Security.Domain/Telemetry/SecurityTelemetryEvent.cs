namespace HIP.Security.Domain.Telemetry;

public sealed record SecurityTelemetryEvent(
    Guid Id,
    string EventType,
    string Source,
    string Payload,
    DateTimeOffset OccurredAtUtc,
    Guid? ScenarioId = null,
    Guid? PolicyId = null);
