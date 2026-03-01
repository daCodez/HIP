using System.Threading;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

/// <summary>
/// Represents a publicly visible API member.
/// </summary>
public sealed class InMemorySecurityEventCounter : ISecurityEventCounter
{
    private long _replayDetected;
    private long _messageExpired;
    private long _policyBlocked;

    /// <summary>
    /// Increments the counter that tracks replay-detected security events.
    /// </summary>
    public void IncrementReplayDetected() => Interlocked.Increment(ref _replayDetected);

    /// <summary>
    /// Increments the counter that tracks expired-message security events.
    /// </summary>
    public void IncrementMessageExpired() => Interlocked.Increment(ref _messageExpired);

    /// <summary>
    /// Increments the counter that tracks policy-blocked security events.
    /// </summary>
    public void IncrementPolicyBlocked() => Interlocked.Increment(ref _policyBlocked);

    /// <summary>
    /// Executes the operation for this public API member.
    /// </summary>
    /// <returns>The operation result.</returns>
    public SecurityEventSnapshot Snapshot() => new(
        ReplayDetected: Interlocked.Read(ref _replayDetected),
        MessageExpired: Interlocked.Read(ref _messageExpired),
        PolicyBlocked: Interlocked.Read(ref _policyBlocked),
        UtcTimestamp: DateTimeOffset.UtcNow);
}
