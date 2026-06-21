using HIP.Application.SiteSafety;
using Microsoft.Extensions.Options;

namespace HIP.SandboxWorker;

/// <summary>
/// Controls how the local sandbox worker drains privacy-safe link scan work.
/// </summary>
/// <param name="Enabled">Whether the worker should inspect the sandbox queue.</param>
/// <param name="BatchSize">Maximum number of queued requests handled in one loop.</param>
/// <param name="IdleDelayMilliseconds">Delay between empty queue checks.</param>
/// <param name="ExecuteBrowserSandbox">Whether the worker may run a future hardened browser sandbox.</param>
/// <param name="MaxExecutionSeconds">Maximum future sandbox execution time per request.</param>
public sealed record SandboxWorkerOptions(
    bool Enabled = true,
    int BatchSize = 5,
    int IdleDelayMilliseconds = 5000,
    bool ExecuteBrowserSandbox = false,
    int MaxExecutionSeconds = 15)
{
    /// <summary>
    /// Configuration section name used by appsettings, environment variables, and Aspire.
    /// </summary>
    public const string SectionName = "SandboxWorker";

    /// <summary>
    /// Validates bounded worker settings so a bad environment variable cannot create a tight loop or huge batch.
    /// </summary>
    /// <param name="options">Options bound from configuration.</param>
    /// <returns>True when the settings are safe for local development.</returns>
    public static bool Validate(SandboxWorkerOptions options) =>
        options.BatchSize is >= 1 and <= 50
        && options.IdleDelayMilliseconds is >= 250 and <= 60000
        && options.MaxExecutionSeconds is >= 1 and <= 120;
}

/// <summary>
/// Background worker that consumes queued sandbox link scan requests outside the API request path.
/// </summary>
/// <remarks>
/// New code, 2026-06-21 16:20 UTC, HIP Development Team: This worker is the first separate "inspection room"
/// for risky links. It does not browse links yet; it safely drains queued requests and keeps logs free of page text,
/// form values, passwords, tokens, cookies, and raw URLs.
/// </remarks>
public sealed class SandboxLinkScanWorker(
    IServiceScopeFactory scopeFactory,
    IOptionsMonitor<SandboxWorkerOptions> options,
    ILogger<SandboxLinkScanWorker> logger) : BackgroundService
{
    /// <summary>
    /// Runs the worker loop until the host shuts down.
    /// </summary>
    /// <param name="stoppingToken">Token that signals application shutdown.</param>
    /// <returns>A task that represents the running worker.</returns>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("HIP sandbox link scan worker starting.");

        while (!stoppingToken.IsCancellationRequested)
        {
            var currentOptions = options.CurrentValue;
            if (!currentOptions.Enabled)
            {
                await DelayAsync(currentOptions, stoppingToken);
                continue;
            }

            var processed = await ProcessBatchAsync(currentOptions, stoppingToken);
            if (processed == 0)
            {
                await DelayAsync(currentOptions, stoppingToken);
            }
        }
    }

    /// <summary>
    /// Dequeues and records one bounded batch of sandbox work without exposing raw browsing data.
    /// </summary>
    /// <param name="currentOptions">Current worker options from configuration.</param>
    /// <param name="cancellationToken">Token used to cancel the batch.</param>
    /// <returns>The number of requests handled.</returns>
    internal async Task<int> ProcessBatchAsync(SandboxWorkerOptions currentOptions, CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var queue = scope.ServiceProvider.GetRequiredService<ISandboxLinkScanQueue>();
        var requests = await queue.DequeueBatchAsync(currentOptions.BatchSize, cancellationToken);

        foreach (var request in requests)
        {
            LogSafeSandboxRequest(request, currentOptions);
        }

        return requests.Count;
    }

    /// <summary>
    /// Writes a safe operational log for one sandbox request.
    /// </summary>
    /// <param name="request">Queued request being handled.</param>
    /// <param name="currentOptions">Current worker options.</param>
    private void LogSafeSandboxRequest(SandboxLinkScanRequest request, SandboxWorkerOptions currentOptions)
    {
        if (!currentOptions.ExecuteBrowserSandbox)
        {
            logger.LogInformation(
                "Sandbox request {RequestId} for domain {Domain} was accepted in dry-run mode with reason {Reason} and source status {SourceStatus}.",
                request.RequestId,
                request.Domain,
                request.Reason,
                request.SourceStatus);
            return;
        }

        logger.LogWarning(
            "Sandbox request {RequestId} for domain {Domain} requested browser execution, but the hardened browser runner is not implemented yet.",
            request.RequestId,
            request.Domain);
    }

    /// <summary>
    /// Waits between queue checks with a bounded delay.
    /// </summary>
    /// <param name="currentOptions">Current worker options.</param>
    /// <param name="cancellationToken">Token used to cancel the delay.</param>
    /// <returns>A task that completes after the delay or cancellation.</returns>
    private static Task DelayAsync(SandboxWorkerOptions currentOptions, CancellationToken cancellationToken) =>
        Task.Delay(TimeSpan.FromMilliseconds(currentOptions.IdleDelayMilliseconds), cancellationToken);
}
