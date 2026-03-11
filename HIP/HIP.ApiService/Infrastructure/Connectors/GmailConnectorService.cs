using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using HIP.Audit.Abstractions;
using HIP.Audit.Models;

namespace HIP.ApiService.Infrastructure.Connectors;

/// <summary>
/// Runtime status payload for the Gmail connector.
/// </summary>
internal sealed record GmailConnectorStatus(
    bool Configured,
    bool Connected,
    string? LastError,
    DateTimeOffset? LastPolledAtUtc,
    DateTimeOffset? AccessTokenExpiresAtUtc,
    string StorePath);

/// <summary>
/// Orchestrates OAuth, token refresh, and Gmail metadata polling.
/// </summary>
internal sealed class GmailConnectorService
{
    private const string Scope = "https://www.googleapis.com/auth/gmail.readonly";
    private readonly GmailConnectorOptions _options;
    private readonly GmailTokenStore _store;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IAuditTrail _auditTrail;
    private readonly ILogger<GmailConnectorService> _logger;
    private readonly Dictionary<string, DateTimeOffset> _states = new(StringComparer.Ordinal);
    private readonly object _stateLock = new();

    /// <summary>
    /// Creates a Gmail connector runtime service.
    /// </summary>
    public GmailConnectorService(
        GmailConnectorOptions options,
        GmailTokenStore store,
        IHttpClientFactory httpClientFactory,
        IAuditTrail auditTrail,
        ILogger<GmailConnectorService> logger)
    {
        _options = options;
        _store = store;
        _httpClientFactory = httpClientFactory;
        _auditTrail = auditTrail;
        _logger = logger;
    }

    /// <summary>
    /// Builds status information for admin endpoint.
    /// </summary>
    public async Task<GmailConnectorStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        var connected = !string.IsNullOrWhiteSpace(state.RefreshToken);
        var lastError = state.LastError;
        if (_options.IsConfigured && string.Equals(lastError, "Missing OAuth environment variables.", StringComparison.OrdinalIgnoreCase))
        {
            lastError = null;
        }

        return new GmailConnectorStatus(
            Configured: _options.IsConfigured,
            Connected: connected,
            LastError: !string.IsNullOrWhiteSpace(lastError)
                ? lastError
                : _options.IsConfigured ? null : "OAuth env vars missing",
            LastPolledAtUtc: state.LastPolledAtUtc,
            AccessTokenExpiresAtUtc: state.AccessTokenExpiresAtUtc,
            StorePath: _store.GetPath());
    }

    /// <summary>
    /// Creates OAuth consent URL and stores state token.
    /// </summary>
    public string BuildAuthorizeUrl()
    {
        if (!_options.IsConfigured)
        {
            throw new InvalidOperationException("Gmail connector is not configured.");
        }

        var state = Guid.NewGuid().ToString("n");
        lock (_stateLock)
        {
            _states[state] = DateTimeOffset.UtcNow.AddMinutes(10);
        }

        var query = new Dictionary<string, string>
        {
            ["client_id"] = _options.ClientId!,
            ["redirect_uri"] = _options.RedirectUri!,
            ["response_type"] = "code",
            ["scope"] = Scope,
            ["access_type"] = "offline",
            ["prompt"] = "consent",
            ["include_granted_scopes"] = "true",
            ["state"] = state
        };

        var queryString = string.Join("&", query.Select(x => $"{Uri.EscapeDataString(x.Key)}={Uri.EscapeDataString(x.Value)}"));
        return $"https://accounts.google.com/o/oauth2/v2/auth?{queryString}";
    }

    /// <summary>
    /// Exchanges auth code for tokens and persists connector credentials.
    /// </summary>
    public async Task<(bool Success, string Message)> CompleteOAuthAsync(string? code, string? state, CancellationToken cancellationToken)
    {
        if (!_options.IsConfigured)
        {
            return (false, "Missing GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET / GOOGLE_OAUTH_REDIRECT_URI");
        }

        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state) || !ConsumeState(state))
        {
            return (false, "Invalid OAuth callback state or missing code.");
        }

        var payload = new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = _options.ClientId!,
            ["client_secret"] = _options.ClientSecret!,
            ["redirect_uri"] = _options.RedirectUri!,
            ["grant_type"] = "authorization_code"
        };

        var client = _httpClientFactory.CreateClient();
        using var response = await client.PostAsync("https://oauth2.googleapis.com/token", new FormUrlEncodedContent(payload), cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            await PersistErrorAsync($"OAuth token exchange failed: {(int)response.StatusCode}", cancellationToken);
            return (false, "OAuth token exchange failed.");
        }

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;

        var accessToken = root.TryGetProperty("access_token", out var accessEl) ? accessEl.GetString() : null;
        var refreshToken = root.TryGetProperty("refresh_token", out var refreshEl) ? refreshEl.GetString() : null;
        var expiresIn = root.TryGetProperty("expires_in", out var expiresEl) ? expiresEl.GetInt32() : 3600;
        var scope = root.TryGetProperty("scope", out var scopeEl) ? scopeEl.GetString() : Scope;
        var tokenType = root.TryGetProperty("token_type", out var typeEl) ? typeEl.GetString() : "Bearer";

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            await PersistErrorAsync("OAuth exchange response missing access_token.", cancellationToken);
            return (false, "OAuth callback did not return access token.");
        }

        var existing = await _store.ReadAsync(cancellationToken);
        existing.AccessToken = accessToken;
        existing.RefreshToken = string.IsNullOrWhiteSpace(refreshToken) ? existing.RefreshToken : refreshToken;
        existing.AccessTokenExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Max(30, expiresIn - 30));
        existing.Scope = scope;
        existing.TokenType = tokenType;
        existing.LastError = null;

        await _store.WriteAsync(existing, cancellationToken);

        await _auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: "connector.gmail.oauth.connected",
            Subject: "gmail.connector",
            Source: "admin",
            Detail: "Gmail connector OAuth completed",
            Category: "connector",
            Outcome: "ok",
            ReasonCode: "gmail.oauth.connected",
            Route: "/api/admin/connectors/gmail/oauth/callback",
            CorrelationId: Activity.Current?.TraceId.ToString()), cancellationToken);

        return (true, "Gmail connector connected.");
    }

    /// <summary>
    /// Performs one metadata polling pass and emits audit events.
    /// </summary>
    public async Task PollOnceAsync(CancellationToken cancellationToken)
    {
        if (!_options.IsConfigured)
        {
            await PersistErrorAsync("Missing OAuth environment variables.", cancellationToken);
            return;
        }

        var state = await EnsureAccessTokenAsync(cancellationToken);
        if (state is null || string.IsNullOrWhiteSpace(state.AccessToken))
        {
            return;
        }

        try
        {
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", state.AccessToken);

            var listUrl = $"https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults={_options.MaxMessagesPerPoll}&includeSpamTrash=false";
            using var listResponse = await client.GetAsync(listUrl, cancellationToken);
            var listContent = await listResponse.Content.ReadAsStringAsync(cancellationToken);

            if (!listResponse.IsSuccessStatusCode)
            {
                await PersistErrorAsync($"Gmail list failed: {(int)listResponse.StatusCode}", cancellationToken);
                return;
            }

            using var listDoc = JsonDocument.Parse(listContent);
            if (!listDoc.RootElement.TryGetProperty("messages", out var messagesEl) || messagesEl.ValueKind != JsonValueKind.Array)
            {
                state.LastPolledAtUtc = DateTimeOffset.UtcNow;
                state.LastError = null;
                await _store.WriteAsync(state, cancellationToken);
                return;
            }

            var knownIds = new HashSet<string>(state.RecentMessageIds, StringComparer.Ordinal);

            foreach (var msg in messagesEl.EnumerateArray())
            {
                if (!msg.TryGetProperty("id", out var idEl))
                {
                    continue;
                }

                var messageId = idEl.GetString();
                if (string.IsNullOrWhiteSpace(messageId) || knownIds.Contains(messageId))
                {
                    continue;
                }

                await ProcessMessageAsync(client, messageId, state, knownIds, cancellationToken);
            }

            state.LastPolledAtUtc = DateTimeOffset.UtcNow;
            state.LastError = null;
            state.RecentMessageIds = knownIds.TakeLast(1000).ToList();
            await _store.WriteAsync(state, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Gmail connector poll failed.");
            await PersistErrorAsync("Gmail poll failed.", cancellationToken);
        }
    }

    private async Task ProcessMessageAsync(HttpClient client, string messageId, GmailConnectorState state, HashSet<string> knownIds, CancellationToken cancellationToken)
    {
        var metadataUrl = $"https://gmail.googleapis.com/gmail/v1/users/me/messages/{Uri.EscapeDataString(messageId)}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date";
        using var detailResponse = await client.GetAsync(metadataUrl, cancellationToken);
        if (!detailResponse.IsSuccessStatusCode)
        {
            return;
        }

        var content = await detailResponse.Content.ReadAsStringAsync(cancellationToken);
        using var detailDoc = JsonDocument.Parse(content);
        var root = detailDoc.RootElement;

        var internalDateMs = root.TryGetProperty("internalDate", out var dateEl)
            && long.TryParse(dateEl.GetString(), out var parsedDate)
            ? parsedDate
            : 0;

        if (internalDateMs > 0 && internalDateMs <= state.LastSeenInternalDateMs)
        {
            knownIds.Add(messageId);
            return;
        }

        var labels = root.TryGetProperty("labelIds", out var labelsEl) && labelsEl.ValueKind == JsonValueKind.Array
            ? labelsEl.EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : [];

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("payload", out var payloadEl) && payloadEl.ValueKind == JsonValueKind.Object &&
            payloadEl.TryGetProperty("headers", out var headersEl) && headersEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var h in headersEl.EnumerateArray())
            {
                var name = h.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
                var value = h.TryGetProperty("value", out var valueEl) ? valueEl.GetString() : null;
                if (!string.IsNullOrWhiteSpace(name) && value is not null)
                {
                    headers[name] = value;
                }
            }
        }

        var from = headers.GetValueOrDefault("From") ?? "unknown";
        var subject = headers.GetValueOrDefault("Subject") ?? "(no subject)";
        var eventType = labels.Contains("SENT") ? "connector.gmail.email.sent" : "connector.gmail.email.received";
        var category = labels.Contains("SENT") ? "email" : "inbox";
        var reasonCode = labels.Contains("SENT") ? "gmail.message.sent" : "gmail.message.received";

        var normalizedSubject = subject.ToLowerInvariant();
        if (from.Contains("accounts.google.com", StringComparison.OrdinalIgnoreCase)
            || normalizedSubject.Contains("security alert")
            || normalizedSubject.Contains("new sign-in"))
        {
            eventType = "connector.gmail.account.security_alert";
            category = "security";
            reasonCode = "gmail.account.security_alert";
        }

        await _auditTrail.AppendAsync(new AuditEvent(
            Id: Guid.NewGuid().ToString("n"),
            CreatedAtUtc: DateTimeOffset.UtcNow,
            EventType: eventType,
            Subject: "gmail.personal",
            Source: "gmail",
            Detail: $"messageId={messageId}; from={Truncate(from, 160)}; subject={Truncate(subject, 200)}",
            Category: category,
            Outcome: "observed",
            ReasonCode: reasonCode,
            Route: "/api/admin/connectors/gmail/poller",
            CorrelationId: Activity.Current?.TraceId.ToString()),
            cancellationToken);

        if (internalDateMs > state.LastSeenInternalDateMs)
        {
            state.LastSeenInternalDateMs = internalDateMs;
        }

        knownIds.Add(messageId);
    }

    private async Task<GmailConnectorState?> EnsureAccessTokenAsync(CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(state.RefreshToken) && string.IsNullOrWhiteSpace(state.AccessToken))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(state.AccessToken) && state.AccessTokenExpiresAtUtc > DateTimeOffset.UtcNow.AddMinutes(1))
        {
            return state;
        }

        if (string.IsNullOrWhiteSpace(state.RefreshToken))
        {
            await PersistErrorAsync("Missing refresh token; reconnect OAuth.", cancellationToken);
            return null;
        }

        var payload = new Dictionary<string, string>
        {
            ["client_id"] = _options.ClientId!,
            ["client_secret"] = _options.ClientSecret!,
            ["refresh_token"] = state.RefreshToken,
            ["grant_type"] = "refresh_token"
        };

        var client = _httpClientFactory.CreateClient();
        using var response = await client.PostAsync("https://oauth2.googleapis.com/token", new FormUrlEncodedContent(payload), cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            await PersistErrorAsync($"Token refresh failed: {(int)response.StatusCode}", cancellationToken);
            return null;
        }

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;
        var accessToken = root.TryGetProperty("access_token", out var accessEl) ? accessEl.GetString() : null;
        var expiresIn = root.TryGetProperty("expires_in", out var expiresEl) ? expiresEl.GetInt32() : 3600;
        var tokenType = root.TryGetProperty("token_type", out var typeEl) ? typeEl.GetString() : "Bearer";

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            await PersistErrorAsync("Token refresh response missing access_token.", cancellationToken);
            return null;
        }

        state.AccessToken = accessToken;
        state.TokenType = tokenType;
        state.AccessTokenExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Max(30, expiresIn - 30));
        state.LastError = null;
        await _store.WriteAsync(state, cancellationToken);
        return state;
    }

    private bool ConsumeState(string state)
    {
        lock (_stateLock)
        {
            var now = DateTimeOffset.UtcNow;
            var expired = _states.Where(x => x.Value < now).Select(x => x.Key).ToArray();
            foreach (var key in expired)
            {
                _states.Remove(key);
            }

            if (!_states.TryGetValue(state, out var expiresAt) || expiresAt < now)
            {
                return false;
            }

            _states.Remove(state);
            return true;
        }
    }

    private async Task PersistErrorAsync(string error, CancellationToken cancellationToken)
    {
        var state = await _store.ReadAsync(cancellationToken);
        state.LastError = error;
        await _store.WriteAsync(state, cancellationToken);
    }

    private static string Truncate(string value, int max)
    {
        if (value.Length <= max)
        {
            return value;
        }

        return string.Concat(value.AsSpan(0, max), "...");
    }
}
