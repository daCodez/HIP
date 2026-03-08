using System.Collections.Concurrent;
using HIP.RateLimitGuard.Abstractions;

namespace HIP.RateLimitGuard.Stores;

public sealed class InMemoryInflightStore : IInflightStore
{
    private readonly ConcurrentDictionary<string, InflightEntry> _map = new(StringComparer.Ordinal);

    public Task<bool> TryAddAsync(string key, InflightEntry entry, CancellationToken ct = default)
        => Task.FromResult(_map.TryAdd(key, entry));

    public Task<InflightEntry?> GetAsync(string key, CancellationToken ct = default)
        => Task.FromResult(_map.TryGetValue(key, out var value) ? value : null);

    public Task RemoveAsync(string key, CancellationToken ct = default)
    {
        _map.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<int> CountByPrefixAsync(string prefix, CancellationToken ct = default)
        => Task.FromResult(_map.Keys.Count(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)));
}

public sealed class InMemoryBudgetStore : IBudgetStore
{
    private readonly ConcurrentDictionary<string, (long value, DateTimeOffset started)> _map = new(StringComparer.Ordinal);

    public Task<WindowCounterResult> IncrementAsync(string key, long amount, TimeSpan window, DateTimeOffset now, CancellationToken ct = default)
    {
        while (true)
        {
            var current = _map.GetOrAdd(key, _ => (0, now));
            var active = now - current.started > window ? (0L, now) : current;
            var next = (active.Item1 + amount, active.Item2);
            if (_map.TryUpdate(key, next, current) || (_map[key] == next))
            {
                return Task.FromResult(new WindowCounterResult(next.Item1, next.Item2));
            }
        }
    }
}

public sealed class InMemoryCooldownStore : ICooldownStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _map = new(StringComparer.Ordinal);

    public Task<DateTimeOffset?> GetUntilAsync(string key, DateTimeOffset now, CancellationToken ct = default)
    {
        if (_map.TryGetValue(key, out var until) && until > now) return Task.FromResult<DateTimeOffset?>(until);
        _map.TryRemove(key, out _);
        return Task.FromResult<DateTimeOffset?>(null);
    }

    public Task SetUntilAsync(string key, DateTimeOffset until, CancellationToken ct = default)
    {
        _map[key] = until;
        return Task.CompletedTask;
    }
}

public sealed class InMemoryCacheStore : ICacheStore
{
    private readonly ConcurrentDictionary<string, CacheEntry> _map = new(StringComparer.Ordinal);

    public Task<CacheEntry?> GetAsync(string key, DateTimeOffset now, CancellationToken ct = default)
    {
        if (_map.TryGetValue(key, out var entry) && entry.StaleUntil > now) return Task.FromResult<CacheEntry?>(entry);
        _map.TryRemove(key, out _);
        return Task.FromResult<CacheEntry?>(null);
    }

    public Task SetAsync(string key, CacheEntry entry, CancellationToken ct = default)
    {
        _map[key] = entry;
        return Task.CompletedTask;
    }
}
