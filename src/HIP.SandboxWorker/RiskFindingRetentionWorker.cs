using HIP.Application.Reporting;
using Microsoft.Extensions.Options;

namespace HIP.SandboxWorker;

public sealed record RiskFindingRetentionWorkerOptions(
    bool Enabled = true,
    int BatchSize = 250,
    int IntervalMinutes = 360)
{
    /// <summary>
    /// Creates default options for .NET configuration binding, which requires a parameterless constructor.
    /// </summary>
    public RiskFindingRetentionWorkerOptions()
        : this(true, 250, 360)
    {
    }

    public const string SectionName = "RiskFindingRetentionWorker";
    public static bool Validate(RiskFindingRetentionWorkerOptions options) =>
        options.BatchSize is >= 1 and <= 1000 && options.IntervalMinutes is >= 5 and <= 1440;
}

/// <summary>Periodically removes expired privacy-sensitive risk findings in bounded batches.</summary>
public sealed class RiskFindingRetentionWorker(
    IServiceScopeFactory scopeFactory,
    IOptionsMonitor<RiskFindingRetentionWorkerOptions> options,
    ILogger<RiskFindingRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var current = options.CurrentValue;
            if (current.Enabled)
            {
                using var scope = scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<IRiskFindingRetentionService>();
                var reports = scope.ServiceProvider.GetRequiredService<IPrivacySafeReportService>();
                var deletedRiskFindings = await service.DeleteExpiredBatchAsync(current.BatchSize, stoppingToken);
                var deletedReports = await reports.DeleteExpiredAsync(DateTimeOffset.UtcNow, current.BatchSize, stoppingToken);
                var deleted = deletedRiskFindings + deletedReports;
                if (deleted > 0) logger.LogInformation("Deleted {DeletedCount} expired privacy-safe report records.", deleted);
            }

            await Task.Delay(TimeSpan.FromMinutes(current.IntervalMinutes), stoppingToken);
        }
    }
}
