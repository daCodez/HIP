using HIP.Application.Security;

namespace HIP.Infrastructure.Security;

/// <summary>
/// Uses Redis-backed atomic expiry state to suppress duplicate submissions across HIP instances.
/// </summary>
public sealed class RedisDuplicateSubmissionGuard(IAtomicExpiryStore atomicStore) : IDuplicateSubmissionGuard
{
    /// <inheritdoc />
    public ValueTask<bool> TryAcceptAsync(
        string scope,
        IEnumerable<string?> parts,
        TimeSpan window,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentNullException.ThrowIfNull(parts);
        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window), window, "Duplicate window must be positive.");
        }

        var normalizedParts = parts.Select(part => (part ?? string.Empty).Trim().ToLowerInvariant());
        var fingerprint = SecurityStateKey.Fingerprint("duplicate", scope.Trim().ToLowerInvariant(), normalizedParts);
        return atomicStore.TryCreateAsync($"hip:v1:duplicate:{fingerprint}", window, cancellationToken);
    }
}

/// <summary>
/// Uses Redis-backed atomic expiry state to reject issuer-scoped nonce replay across HIP instances.
/// </summary>
public sealed class RedisReplayNonceStore(IAtomicExpiryStore atomicStore) : IReplayNonceStore
{
    /// <inheritdoc />
    public ValueTask<bool> TryReserveAsync(
        string issuer,
        string nonce,
        TimeSpan validityWindow,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        if (validityWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(validityWindow),
                validityWindow,
                "Nonce validity must be positive.");
        }

        var fingerprint = SecurityStateKey.Fingerprint("nonce", issuer, [nonce]);
        return atomicStore.TryCreateAsync($"hip:v1:nonce:{fingerprint}", validityWindow, cancellationToken);
    }
}
