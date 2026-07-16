namespace HIP.Application.Security;

/// <summary>
/// Atomically reserves protocol nonces so a signed message cannot be replayed across HIP instances.
/// </summary>
public interface IReplayNonceStore
{
    /// <summary>
    /// Attempts to reserve an issuer-scoped nonce for its complete validity window.
    /// </summary>
    ValueTask<bool> TryReserveAsync(
        string issuer,
        string nonce,
        TimeSpan validityWindow,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// In-memory replay nonce store for explicit isolated tests.
/// </summary>
public sealed class InMemoryReplayNonceStore(TimeProvider? timeProvider = null) : IReplayNonceStore
{
    private readonly Dictionary<string, DateTimeOffset> reservedUntil = new(StringComparer.Ordinal);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly object sync = new();

    /// <inheritdoc />
    public ValueTask<bool> TryReserveAsync(
        string issuer,
        string nonce,
        TimeSpan validityWindow,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        if (validityWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(validityWindow),
                validityWindow,
                "Nonce validity must be positive.");
        }

        var key = SecurityStateKey.Fingerprint("nonce", issuer, [nonce]);
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
