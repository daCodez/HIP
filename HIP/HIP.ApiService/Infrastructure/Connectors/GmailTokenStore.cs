using System.Text.Json;

namespace HIP.ApiService.Infrastructure.Connectors;

/// <summary>
/// Persisted connector token and cursor state for Gmail polling.
/// </summary>
internal sealed class GmailConnectorState
{
    /// <summary>
    /// Access token used for Gmail API calls.
    /// </summary>
    public string? AccessToken { get; set; }

    /// <summary>
    /// Refresh token used to obtain new access tokens.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// UTC access token expiration.
    /// </summary>
    public DateTimeOffset? AccessTokenExpiresAtUtc { get; set; }

    /// <summary>
    /// Token type reported by Google (typically Bearer).
    /// </summary>
    public string? TokenType { get; set; }

    /// <summary>
    /// Granted OAuth scope string.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Last connector error text for status reporting.
    /// </summary>
    public string? LastError { get; set; }

    /// <summary>
    /// UTC time of most recent successful poll.
    /// </summary>
    public DateTimeOffset? LastPolledAtUtc { get; set; }

    /// <summary>
    /// Internal date watermark in Unix milliseconds for de-duplication.
    /// </summary>
    public long LastSeenInternalDateMs { get; set; }

    /// <summary>
    /// Small rolling cache of processed message ids.
    /// </summary>
    public List<string> RecentMessageIds { get; set; } = [];
}

/// <summary>
/// File-backed persistence for Gmail connector token and cursor state.
/// </summary>
internal sealed class GmailTokenStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _sync = new(1, 1);
    private readonly string _path;

    /// <summary>
    /// Creates the store rooted under HIP.ApiService/SecurityEvents.
    /// </summary>
    public GmailTokenStore(IWebHostEnvironment env)
    {
        var directory = Path.Combine(env.ContentRootPath, "SecurityEvents");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "gmail-connector.store.json");
    }

    /// <summary>
    /// Gets current persisted connector state or default empty state.
    /// </summary>
    public async Task<GmailConnectorState> ReadAsync(CancellationToken cancellationToken)
    {
        await _sync.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return new GmailConnectorState();
            }

            await using var stream = File.OpenRead(_path);
            var state = await JsonSerializer.DeserializeAsync<GmailConnectorState>(stream, JsonOptions, cancellationToken);
            return state ?? new GmailConnectorState();
        }
        finally
        {
            _sync.Release();
        }
    }

    /// <summary>
    /// Persists connector state to disk with restricted file permissions when possible.
    /// </summary>
    public async Task WriteAsync(GmailConnectorState state, CancellationToken cancellationToken)
    {
        await _sync.WaitAsync(cancellationToken);
        try
        {
            var tempPath = $"{_path}.tmp";
            await using (var stream = File.Create(tempPath))
            {
                await JsonSerializer.SerializeAsync(stream, state, JsonOptions, cancellationToken);
            }

            File.Move(tempPath, _path, overwrite: true);

            try
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(_path,
                        UnixFileMode.UserRead |
                        UnixFileMode.UserWrite);
                }
            }
            catch
            {
                // Best-effort permissions tightening (non-Unix/runtime dependent).
            }
        }
        finally
        {
            _sync.Release();
        }
    }

    /// <summary>
    /// Returns on-disk store path for diagnostics.
    /// </summary>
    public string GetPath() => _path;
}
