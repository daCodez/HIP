namespace HIP.Shared.Contracts;

/// <summary>
/// Response payload for the HIP admin shell bootstrap endpoint.
/// </summary>
/// <param name="EnabledModules">Modules enabled for the current user/session.</param>
/// <param name="UserRoles">Current user roles available to client-side role-aware navigation.</param>
/// <param name="Metadata">Server-provided metadata for freshness and traceability.</param>
public sealed record AdminShellConfigResponse(
    IReadOnlyList<string> EnabledModules,
    IReadOnlyList<string> UserRoles,
    AdminShellConfigMetadata Metadata);

/// <summary>
/// Response metadata for shell config payloads.
/// </summary>
/// <param name="CorrelationId">Correlation id used for request/response tracing.</param>
/// <param name="ServerTimestampUtc">Server timestamp in UTC for freshness-aware UX.</param>
/// <param name="ConfigVersion">Optional shell config version identifier.</param>
public sealed record AdminShellConfigMetadata(
    string CorrelationId,
    DateTimeOffset ServerTimestampUtc,
    string? ConfigVersion = null);
