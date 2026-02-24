namespace HIP.ApiService.Application.Abstractions;

public interface ISecurityEventCounter
{
    void IncrementReplayDetected();
    void IncrementMessageExpired();
    void IncrementPolicyBlocked();
    SecurityEventSnapshot Snapshot();
}

public sealed record SecurityEventSnapshot(
    long ReplayDetected,
    long MessageExpired,
    long PolicyBlocked,
    DateTimeOffset UtcTimestamp);
