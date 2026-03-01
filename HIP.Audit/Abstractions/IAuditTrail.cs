using HIP.Audit.Models;

namespace HIP.Audit.Abstractions;

/// <summary>
/// Persists and retrieves audit events emitted by HIP request handlers.
/// </summary>
public interface IAuditTrail
{
    /// <summary>
    /// Appends a new audit event to the backing store.
    /// </summary>
    Task AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the most recent audit events up to the provided count.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> RecentAsync(int count, CancellationToken cancellationToken);

    /// <summary>
    /// Queries audit events using bounded filter options.
    /// </summary>
    Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken);
}
