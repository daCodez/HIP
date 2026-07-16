using HIP.Application.Security;
using StackExchange.Redis;

namespace HIP.Infrastructure.Security;

/// <summary>
/// Implements atomic expiring security state with Redis SET NX.
/// </summary>
public sealed class RedisAtomicExpiryStore(IConnectionMultiplexer connectionMultiplexer) : IAtomicExpiryStore
{
    private readonly IDatabase database = connectionMultiplexer.GetDatabase();

    /// <inheritdoc />
    public async ValueTask<bool> TryCreateAsync(
        string key,
        TimeSpan timeToLive,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (timeToLive <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeToLive),
                timeToLive,
                "Redis security-state expiry must be positive.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        return await database.StringSetAsync(
            key,
            RedisValue.EmptyString,
            expiry: timeToLive,
            when: When.NotExists,
            flags: CommandFlags.DemandMaster);
    }
}
