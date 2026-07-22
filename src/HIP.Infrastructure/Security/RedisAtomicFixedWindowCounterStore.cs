using HIP.Application.ServiceClients;
using StackExchange.Redis;

namespace HIP.Infrastructure.Security;

/// <summary>
/// Implements a distributed fixed-window counter using one atomic Redis script.
/// </summary>
public sealed class RedisAtomicFixedWindowCounterStore(IConnectionMultiplexer connectionMultiplexer)
    : IAtomicFixedWindowCounterStore
{
    private const int MaximumKeyUtf8Bytes = 512;

    // The expiry is intentionally relative to the first increment. No process wall clock or cross-host clock
    // alignment participates in the security decision.
    private const string IncrementWithFirstExpiryScript = """
        local current = redis.call('INCR', KEYS[1])
        if current == 1 then
            redis.call('PEXPIRE', KEYS[1], ARGV[1])
        end
        return current
        """;

    private readonly IDatabase database = connectionMultiplexer.GetDatabase();

    /// <inheritdoc />
    public async ValueTask<long> IncrementAsync(
        string key,
        TimeSpan window,
        CancellationToken cancellationToken = default)
    {
        ValidateKey(key);
        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(window),
                window,
                "Redis fixed-window counter expiry must be positive.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var expiryMilliseconds = checked((long)Math.Ceiling(window.TotalMilliseconds));
        var result = await database.ScriptEvaluateAsync(
                IncrementWithFirstExpiryScript,
                [key],
                [expiryMilliseconds],
                CommandFlags.DemandMaster)
            .WaitAsync(cancellationToken);

        return (long)result;
    }

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (System.Text.Encoding.UTF8.GetByteCount(key) > MaximumKeyUtf8Bytes ||
            key.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            throw new ArgumentException("Redis fixed-window counter key is not in a bounded canonical form.", nameof(key));
        }
    }
}
