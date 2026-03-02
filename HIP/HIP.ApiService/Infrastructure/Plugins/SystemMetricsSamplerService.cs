using Microsoft.Extensions.Hosting;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Background sampler that records CPU and memory usage.
/// </summary>
public sealed class SystemMetricsSamplerService(SystemMetricsStore store, ILogger<SystemMetricsSamplerService> logger) : BackgroundService
{
    private long _prevIdle;
    private long _prevTotal;

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        InitializeCpuSnapshot();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var cpu = ReadCpuPercent();
                var mem = ReadMemoryPercent();
                store.Add(new SystemMetricSample(DateTimeOffset.UtcNow, cpu, mem));
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "System metrics sample failed");
            }

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }

    private void InitializeCpuSnapshot()
    {
        var (idle, total) = ReadCpuTicks();
        _prevIdle = idle;
        _prevTotal = total;
    }

    private double ReadCpuPercent()
    {
        var (idle, total) = ReadCpuTicks();
        var idleDiff = idle - _prevIdle;
        var totalDiff = total - _prevTotal;

        _prevIdle = idle;
        _prevTotal = total;

        if (totalDiff <= 0) return 0;
        var usage = 100.0 * (1.0 - (double)idleDiff / totalDiff);
        return Math.Clamp(usage, 0, 100);
    }

    private static (long Idle, long Total) ReadCpuTicks()
    {
        var line = File.ReadLines("/proc/stat").First();
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(long.Parse).ToArray();
        var idle = parts[3] + (parts.Length > 4 ? parts[4] : 0);
        var total = parts.Sum();
        return (idle, total);
    }

    private static double ReadMemoryPercent()
    {
        long total = 0;
        long available = 0;

        foreach (var line in File.ReadLines("/proc/meminfo"))
        {
            if (line.StartsWith("MemTotal:"))
            {
                total = ParseKb(line);
            }
            else if (line.StartsWith("MemAvailable:"))
            {
                available = ParseKb(line);
            }

            if (total > 0 && available > 0) break;
        }

        if (total <= 0) return 0;
        var used = total - available;
        return Math.Clamp((double)used / total * 100.0, 0, 100);
    }

    private static long ParseKb(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && long.TryParse(parts[1], out var kb) ? kb : 0;
    }
}
