using HIP.Application.SiteSafety;
using Microsoft.Extensions.Options;

namespace HIP.SandboxWorker;

/// <summary>Consumes durable external provider jobs outside API and Web request paths.</summary>
public sealed class ExternalSiteEvidenceJobWorker(
    IServiceScopeFactory scopeFactory,
    IOptionsMonitor<SandboxWorkerOptions> workerOptions,
    ILogger<ExternalSiteEvidenceJobWorker> logger) : BackgroundService
{
    private readonly string workerId = $"provider-worker:{Guid.NewGuid():N}";

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("HIP external site evidence job worker starting.");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processed = await ProcessOnceAsync(stoppingToken);
                if (!processed)
                {
                    await Task.Delay(workerOptions.CurrentValue.IdleDelayMilliseconds, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "HIP external provider job loop failed safely.");
                await Task.Delay(workerOptions.CurrentValue.IdleDelayMilliseconds, stoppingToken);
            }
        }
    }

    /// <summary>Processes at most one ready job through a fresh dependency-injection scope.</summary>
    public async Task<bool> ProcessOnceAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var processor = scope.ServiceProvider.GetRequiredService<ExternalSiteEvidenceJobProcessor>();
        return await processor.ProcessNextAsync(workerId, cancellationToken);
    }
}
