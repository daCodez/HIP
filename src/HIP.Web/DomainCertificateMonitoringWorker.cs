using HIP.Application.Certificates;

namespace HIP.Web;

/// <summary>Runs bounded recurring certificate monitoring checks without retaining page content.</summary>
public sealed class DomainCertificateMonitoringWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<DomainCertificateMonitoringWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var coordinator = scope.ServiceProvider
                    .GetRequiredService<IDomainCertificateMonitoringCoordinator>();
                var summary = await coordinator.RunDueAsync(100, stoppingToken).ConfigureAwait(false);
                logger.LogInformation(
                    "HIP monitoring examined {Examined}, checked {Checked}, deferred {Deferred}, and conflicted {Conflicted}.",
                    summary.Examined,
                    summary.Checked,
                    summary.Deferred,
                    summary.Conflicted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "HIP scheduled certificate monitoring failed.");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
        }
    }
}
