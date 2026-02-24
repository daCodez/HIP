using System.Threading;
using HIP.ApiService.Application.Abstractions;

namespace HIP.ApiService.Infrastructure.Security;

public sealed class InMemorySecurityEventCounter : ISecurityEventCounter
{
    private long _replayDetected;
    private long _messageExpired;
    private long _policyBlocked;

    public void IncrementReplayDetected() => Interlocked.Increment(ref _replayDetected);
    public void IncrementMessageExpired() => Interlocked.Increment(ref _messageExpired);
    public void IncrementPolicyBlocked() => Interlocked.Increment(ref _policyBlocked);

    public SecurityEventSnapshot Snapshot() => new(
        ReplayDetected: Interlocked.Read(ref _replayDetected),
        MessageExpired: Interlocked.Read(ref _messageExpired),
        PolicyBlocked: Interlocked.Read(ref _policyBlocked),
        UtcTimestamp: DateTimeOffset.UtcNow);
}
