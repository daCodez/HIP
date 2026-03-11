namespace HIP.ApiService.Infrastructure.Connectors;

/// <summary>
/// Configuration values used by the Gmail personal connector.
/// Values are read from environment variables at runtime.
/// </summary>
internal sealed class GmailConnectorOptions
{
    /// <summary>
    /// OAuth client id for Google OAuth app registration.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// OAuth client secret for Google OAuth app registration.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// OAuth redirect URI registered in Google Cloud Console.
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// Polling interval in minutes.
    /// </summary>
    public int PollIntervalMinutes { get; init; } = 5;

    /// <summary>
    /// Maximum messages requested per polling pass.
    /// </summary>
    public int MaxMessagesPerPoll { get; init; } = 25;

    /// <summary>
    /// Returns true when mandatory OAuth values are configured.
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecret) &&
        !string.IsNullOrWhiteSpace(RedirectUri);

    /// <summary>
    /// Creates options from the current process environment.
    /// </summary>
    public static GmailConnectorOptions FromEnvironment()
    {
        var intervalRaw = Environment.GetEnvironmentVariable("GMAIL_CONNECTOR_POLL_MINUTES");
        var maxRaw = Environment.GetEnvironmentVariable("GMAIL_CONNECTOR_MAX_MESSAGES");

        var interval = int.TryParse(intervalRaw, out var parsedInterval) ? Math.Clamp(parsedInterval, 1, 60) : 5;
        var maxMessages = int.TryParse(maxRaw, out var parsedMax) ? Math.Clamp(parsedMax, 5, 100) : 25;

        return new GmailConnectorOptions
        {
            ClientId = Environment.GetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_ID"),
            ClientSecret = Environment.GetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_SECRET"),
            RedirectUri = Environment.GetEnvironmentVariable("GOOGLE_OAUTH_REDIRECT_URI"),
            PollIntervalMinutes = interval,
            MaxMessagesPerPoll = maxMessages
        };
    }
}
