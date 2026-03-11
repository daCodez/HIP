namespace HIP.ApiService.Infrastructure.Connectors;

/// <summary>
/// Background service that periodically polls Gmail metadata for connector events.
/// </summary>
internal sealed class GmailConnectorPoller : BackgroundService
{
    private readonly GmailConnectorOptions _options;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<GmailConnectorPoller> _logger;

    /// <summary>
    /// Creates a Gmail connector poller.
    /// </summary>
    public GmailConnectorPoller(
        GmailConnectorOptions options,
        IServiceScopeFactory scopeFactory,
        ILogger<GmailConnectorPoller> logger)
    {
        _options = options;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.IsConfigured)
        {
            _logger.LogInformation("Gmail connector poller idle: OAuth env vars not configured.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<GmailConnectorService>();
                await service.PollOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unhandled Gmail poller iteration failure.");
            }

            await Task.Delay(TimeSpan.FromMinutes(_options.PollIntervalMinutes), stoppingToken);
        }
    }
}
