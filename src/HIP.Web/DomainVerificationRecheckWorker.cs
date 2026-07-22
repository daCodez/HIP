using HIP.Application.Identity;

namespace HIP.Web;

/// <summary>Periodically invokes the bounded domain-verification recheck coordinator.</summary>
public sealed class DomainVerificationRecheckWorker(
    IServiceScopeFactory scopeFactory,
    ILogger<DomainVerificationRecheckWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var coordinator = scope.ServiceProvider.GetRequiredService<IDomainVerificationLifecycleCoordinator>();
                var summary = await coordinator.RecheckDueAsync(100, stoppingToken).ConfigureAwait(false);
                logger.LogInformation(
                    "HIP domain verification recheck examined {Examined}, completed {Rechecked}, and failed {Failed}.",
                    summary.Examined,
                    summary.Rechecked,
                    summary.Failed);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "HIP scheduled domain verification recheck failed.");
            }
        }
    }
}
