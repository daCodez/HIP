using System.Collections.Concurrent;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// In-memory rolling store for system metrics samples.
/// </summary>
public sealed class SystemMetricsStore
{
    private readonly ConcurrentQueue<SystemMetricSample> _samples = new();
    private const int MaxSamples = 120;

    /// <summary>
    /// Adds a new metrics sample.
    /// </summary>
    public void Add(SystemMetricSample sample)
    {
        _samples.Enqueue(sample);
        while (_samples.Count > MaxSamples && _samples.TryDequeue(out _)) { }
    }

    /// <summary>
    /// Returns the most recent metrics samples.
    /// </summary>
    public IReadOnlyList<SystemMetricSample> GetRecent(int take)
    {
        var arr = _samples.ToArray();
        var count = Math.Clamp(take, 1, MaxSamples);
        if (arr.Length <= count) return arr;
        return arr[^count..];
    }
}

/// <summary>
/// Point-in-time CPU and memory sample.
/// </summary>
public sealed record SystemMetricSample(DateTimeOffset Utc, double CpuPercent, double MemoryPercent);