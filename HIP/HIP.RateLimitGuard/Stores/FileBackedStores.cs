using System.Text.Json;
using HIP.RateLimitGuard.Abstractions;

namespace HIP.RateLimitGuard.Stores;

internal sealed class FileState<T>
{
    public Dictionary<string, T> Items { get; set; } = new(StringComparer.Ordinal);
}

public abstract class FileBackedStoreBase<T>
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web) { WriteIndented = false };

    protected FileBackedStoreBase(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    }

    protected async Task<TResult> MutateAsync<TResult>(Func<Dictionary<string, T>, TResult> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var data = await ReadAsync(ct).ConfigureAwait(false);
            var result = action(data);
            await WriteAsync(data, ct).ConfigureAwait(false);
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    protected async Task<TResult> ReadOnlyAsync<TResult>(Func<Dictionary<string, T>, TResult> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var data = await ReadAsync(ct).ConfigureAwait(false);
            return action(data);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<Dictionary<string, T>> ReadAsync(CancellationToken ct)
    {
        if (!File.Exists(_path)) return new(StringComparer.Ordinal);
        await using var fs = File.OpenRead(_path);
        var state = await JsonSerializer.DeserializeAsync<FileState<T>>(fs, _json, ct).ConfigureAwait(false);
        return state?.Items ?? new(StringComparer.Ordinal);
    }

    private async Task WriteAsync(Dictionary<string, T> map, CancellationToken ct)
    {
        var tmp = _path + ".tmp";
        await using var fs = File.Create(tmp);
        await JsonSerializer.SerializeAsync(fs, new FileState<T> { Items = map }, _json, ct).ConfigureAwait(false);
        fs.Close();
        File.Move(tmp, _path, true);
    }
}

public sealed class FileBackedInflightStore(string path) : FileBackedStoreBase<InflightEntry>(path), IInflightStore
{
    public Task<bool> TryAddAsync(string key, InflightEntry entry, CancellationToken ct = default)
        => MutateAsync(map =>
        {
            if (map.ContainsKey(key)) return false;
            map[key] = entry;
            return true;
        }, ct);

    public Task<InflightEntry?> GetAsync(string key, CancellationToken ct = default)
        => ReadOnlyAsync(map => map.TryGetValue(key, out var v) ? v : null, ct);

    public Task RemoveAsync(string key, CancellationToken ct = default)
        => MutateAsync(map => { map.Remove(key); return true; }, ct);

    public Task<int> CountByPrefixAsync(string prefix, CancellationToken ct = default)
        => ReadOnlyAsync(map => map.Keys.Count(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)), ct);
}

public sealed class FileBackedBudgetStore(string path) : FileBackedStoreBase<FileBackedBudgetStore.BudgetState>(path), IBudgetStore
{
    public Task<WindowCounterResult> IncrementAsync(string key, long amount, TimeSpan window, DateTimeOffset now, CancellationToken ct = default)
        => MutateAsync(map =>
        {
            map.TryGetValue(key, out var state);
            if (state is null || now - state.StartedAt > window)
            {
                state = new BudgetState(now, 0);
            }

            state = state with { Value = state.Value + amount };
            map[key] = state;
            return new WindowCounterResult(state.Value, state.StartedAt);
        }, ct);

    public sealed record BudgetState(DateTimeOffset StartedAt, long Value);
}

public sealed class FileBackedCooldownStore(string path) : FileBackedStoreBase<DateTimeOffset>(path), ICooldownStore
{
    public Task<DateTimeOffset?> GetUntilAsync(string key, DateTimeOffset now, CancellationToken ct = default)
        => MutateAsync(map =>
        {
            if (!map.TryGetValue(key, out var until) || until <= now)
            {
                map.Remove(key);
                return (DateTimeOffset?)null;
            }

            return until;
        }, ct);

    public Task SetUntilAsync(string key, DateTimeOffset until, CancellationToken ct = default)
        => MutateAsync(map => { map[key] = until; return true; }, ct);
}

public sealed class FileBackedCacheStore(string path) : FileBackedStoreBase<CacheEntry>(path), ICacheStore
{
    public Task<CacheEntry?> GetAsync(string key, DateTimeOffset now, CancellationToken ct = default)
        => MutateAsync(map =>
        {
            if (!map.TryGetValue(key, out var entry) || entry.StaleUntil <= now)
            {
                map.Remove(key);
                return null;
            }

            return entry;
        }, ct);

    public Task SetAsync(string key, CacheEntry entry, CancellationToken ct = default)
        => MutateAsync(map => { map[key] = entry; return true; }, ct);
}
