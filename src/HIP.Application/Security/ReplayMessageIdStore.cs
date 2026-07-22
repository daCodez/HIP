namespace HIP.Application.Security;

/// <summary>
/// Atomically reserves issuer-scoped protocol message identifiers across the envelope validity window.
/// </summary>
public interface IReplayMessageIdStore
{
    ValueTask<bool> TryReserveAsync(
        string issuer,
        string messageId,
        TimeSpan validityWindow,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// In-memory message identifier store for explicit isolated tests.
/// </summary>
public sealed class InMemoryReplayMessageIdStore(TimeProvider? timeProvider = null) : IReplayMessageIdStore
{
    private readonly Dictionary<string, DateTimeOffset> reservedUntil = new(StringComparer.Ordinal);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly object sync = new();

    /// <inheritdoc />
    public ValueTask<bool> TryReserveAsync(
        string issuer,
        string messageId,
        TimeSpan validityWindow,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(messageId);
        if (validityWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(validityWindow),
                validityWindow,
                "Message identifier validity must be positive.");
        }

        var key = SecurityStateKey.Fingerprint("message-id", issuer, [messageId]);
        var now = clock.GetUtcNow();
        lock (sync)
        {
            foreach (var expiredKey in reservedUntil
                         .Where(entry => entry.Value <= now)
                         .Take(100)
                         .Select(entry => entry.Key)
                         .ToArray())
            {
                reservedUntil.Remove(expiredKey);
            }

            if (reservedUntil.TryGetValue(key, out var expiresAt) && expiresAt > now)
            {
                return ValueTask.FromResult(false);
            }

            reservedUntil[key] = now.Add(validityWindow);
            return ValueTask.FromResult(true);
        }
    }
}
