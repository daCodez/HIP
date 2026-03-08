using HIP.RateLimitGuard.Models;

namespace HIP.RateLimitGuard.Abstractions;

public interface IInflightStore
{
    Task<bool> TryAddAsync(string key, InflightEntry entry, CancellationToken ct = default);
    Task<InflightEntry?> GetAsync(string key, CancellationToken ct = default);
    Task RemoveAsync(string key, CancellationToken ct = default);
    Task<int> CountByPrefixAsync(string prefix, CancellationToken ct = default);
}

public interface IBudgetStore
{
    Task<WindowCounterResult> IncrementAsync(string key, long amount, TimeSpan window, DateTimeOffset now, CancellationToken ct = default);
}

public interface ICooldownStore
{
    Task<DateTimeOffset?> GetUntilAsync(string key, DateTimeOffset now, CancellationToken ct = default);
    Task SetUntilAsync(string key, DateTimeOffset until, CancellationToken ct = default);
}

public interface ICacheStore
{
    Task<CacheEntry?> GetAsync(string key, DateTimeOffset now, CancellationToken ct = default);
    Task SetAsync(string key, CacheEntry entry, CancellationToken ct = default);
}

public sealed record InflightEntry(string RequestId, DateTimeOffset CreatedAt, string Fingerprint, string RequestType, string AgentId);

public sealed record CacheEntry(string Key, string Payload, DateTimeOffset CreatedAt, DateTimeOffset FreshUntil, DateTimeOffset StaleUntil);

public sealed record WindowCounterResult(long Value, DateTimeOffset WindowStartedAt);
