using System.Collections.Concurrent;

namespace HIP.ApiService.Infrastructure.Plugins;

/// <summary>
/// Stores transient OAuth state values for CSRF protection.
/// </summary>
public sealed class ChatOAuthStateStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _states = new();

    /// <summary>
    /// Creates and stores a new OAuth state value.
    /// </summary>
    public string Create()
    {
        var state = Guid.NewGuid().ToString("n");
        _states[state] = DateTimeOffset.UtcNow;
        return state;
    }

    /// <summary>
    /// Consumes a previously generated state value.
    /// </summary>
    public bool Consume(string state)
    {
        return _states.TryRemove(state, out _);
    }
}

/// <summary>
/// Stores the active OAuth access token for chat provider calls.
/// </summary>
public sealed class ChatOAuthTokenStore
{
    private string? _accessToken;
    private DateTimeOffset? _expiresAtUtc;

    /// <summary>
    /// Sets the active OAuth access token.
    /// </summary>
    public void Set(string accessToken, DateTimeOffset? expiresAtUtc)
    {
        _accessToken = accessToken;
        _expiresAtUtc = expiresAtUtc;
    }

    /// <summary>
    /// Returns the active OAuth access token and expiry.
    /// </summary>
    public (string? AccessToken, DateTimeOffset? ExpiresAtUtc) Get()
        => (_accessToken, _expiresAtUtc);
}
