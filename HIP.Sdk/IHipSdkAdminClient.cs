using HIP.Audit.Models;

namespace HIP.Sdk;

/// <summary>
/// Defines privileged HIP SDK admin read operations.
/// </summary>
public interface IHipSdkAdminClient
{
    /// <summary>
    /// Retrieves audit events from <c>/api/admin/audit</c> using bounded filters.
    /// </summary>
    /// <param name="query">Audit query options. Null uses server defaults.</param>
    /// <param name="identityId">
    /// Optional admin identity to pass as query parameter when required by server policy.
    /// </param>
    /// <param name="cancellationToken">Cancellation token for the outbound HTTP request.</param>
    /// <returns>List of sanitized audit events ordered by recency.</returns>
    Task<IReadOnlyList<AuditEvent>> GetAuditEventsAsync(
        AuditQuery? query = null,
        string? identityId = null,
        CancellationToken cancellationToken = default);
}
