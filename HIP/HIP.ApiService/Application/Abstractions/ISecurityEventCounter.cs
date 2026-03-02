namespace HIP.ApiService.Application.Abstractions;

/// <summary>
/// Counts core security events for lightweight admin observability.
/// </summary>
public interface ISecurityEventCounter
{
    /// <summary>Increments replay-detected counter.</summary>
    void IncrementReplayDetected();

    /// <summary>Increments expired-message counter.</summary>
    void IncrementMessageExpired();

    /// <summary>Increments policy-blocked counter.</summary>
    void IncrementPolicyBlocked();

    /// <summary>
    /// Returns a point-in-time counter snapshot.
    /// </summary>
    /// <returns>Current counters with snapshot timestamp.</returns>
    SecurityEventSnapshot Snapshot();
}

/// <summary>
/// Snapshot of aggregate security counters.
/// </summary>
/// <param name="ReplayDetected">Total replay detections.</param>
/// <param name="MessageExpired">Total expired-message rejections.</param>
/// <param name="PolicyBlocked">Total policy-based denials.</param>
/// <param name="UtcTimestamp">UTC timestamp of snapshot generation.</param>
public sealed record SecurityEventSnapshot(
    long ReplayDetected,
    long MessageExpired,
    long PolicyBlocked,
    DateTimeOffset UtcTimestamp);
