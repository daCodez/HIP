namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Stores detailed security rejection events for investigation and admin review.
/// </summary>
public interface ISecurityRejectLog
{
    /// <summary>
    /// Appends a new security reject event.
    /// </summary>
    /// <param name="evt">Reject event payload.</param>
    void Add(SecurityRejectEvent evt);

    /// <summary>
    /// Returns recent security reject events.
    /// </summary>
    /// <param name="take">Maximum number of entries to return.</param>
    /// <returns>Recent reject events ordered by recency.</returns>
    IReadOnlyList<SecurityRejectEvent> Recent(int take);
}

/// <summary>
/// Structured detail for a single security rejection.
/// </summary>
/// <param name="Reason">Primary rejection reason.</param>
/// <param name="IdentityId">Identity involved in the rejected action.</param>
/// <param name="MessageId">Optional message id involved in the rejection.</param>
/// <param name="ClockSkewSeconds">Optional clock skew observed during verification.</param>
/// <param name="Classification">Optional classifier label (for replay/severity grouping).</param>
/// <param name="UtcTimestamp">UTC timestamp when rejection occurred.</param>
public sealed record SecurityRejectEvent(
    string Reason,
    string IdentityId,
    string? MessageId,
    double? ClockSkewSeconds,
    string? Classification,
    DateTimeOffset UtcTimestamp);
