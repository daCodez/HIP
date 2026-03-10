using Microsoft.Extensions.Options;

namespace HIP.Agent.Worker;

public sealed class Worker(
    HeartbeatClient heartbeatClient,
    IOptions<AgentOptions> options,
    ILogger<Worker> logger) : BackgroundService
{
    private readonly AgentOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var intervalSeconds = Math.Max(5, _options.HeartbeatIntervalSeconds);
        logger.LogInformation("HIP Agent Worker started. Interval: {IntervalSeconds}s", intervalSeconds);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));

        do
        {
            try
            {
                await heartbeatClient.SendAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Heartbeat send failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
