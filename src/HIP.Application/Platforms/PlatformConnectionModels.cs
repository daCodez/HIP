using System.Text.RegularExpressions;
using HIP.Application.Reporting;

namespace HIP.Application.Platforms;

/// <summary>
/// Supported external platforms that can submit privacy-safe signals to HIP.
/// </summary>
public enum HipPlatformType
{
    /// <summary>
    /// Discord server or bot integration.
    /// </summary>
    Discord = 1
}

/// <summary>
/// Lifecycle state for an admin-configured platform connection.
/// </summary>
public enum HipPlatformConnectionStatus
{
    /// <summary>
    /// The platform has no saved connection metadata.
    /// </summary>
    NotConnected = 0,

    /// <summary>
    /// Admin metadata is saved and HIP can accept privacy-safe submissions for this platform.
    /// </summary>
    Connected = 1,

    /// <summary>
    /// The platform connection is saved but currently disabled.
    /// </summary>
    Disabled = 2
}

/// <summary>
/// Request used by administrators to configure a Discord platform connection.
/// </summary>
/// <param name="GuildId">Discord guild/server id. Stored because it is required to route platform-level submissions.</param>
/// <param name="GuildName">Optional display name shown only in admin surfaces.</param>
/// <param name="ClientId">Optional Discord application client id used to build an install URL.</param>
/// <param name="BotUserId">Optional Discord bot user id for admin troubleshooting.</param>
/// <param name="WebhookUrl">Optional Discord webhook URL. HIP stores only a keyed hash, never the raw URL.</param>
/// <param name="BotToken">Optional bot token marker. HIP records only whether a token was provided and never stores the raw secret.</param>
public sealed record ConnectDiscordPlatformRequest(
    string GuildId,
    string? GuildName,
    string? ClientId,
    string? BotUserId,
    string? WebhookUrl,
    string? BotToken);

/// <summary>
/// Privacy-safe platform connection record persisted by HIP.
/// </summary>
/// <param name="PlatformConnectionId">Stable logical identifier for this platform connection.</param>
/// <param name="PlatformType">Platform type, such as Discord.</param>
/// <param name="DisplayName">Admin-facing display name.</param>
/// <param name="Status">Current connection state.</param>
/// <param name="ExternalWorkspaceId">Platform workspace identifier, such as a Discord guild id.</param>
/// <param name="ExternalWorkspaceName">Optional admin-facing platform workspace name.</param>
/// <param name="ClientId">Optional application client id. This is not a secret.</param>
/// <param name="BotUserId">Optional bot user id. This is not a secret.</param>
/// <param name="BotTokenConfigured">Whether an admin indicated bot credentials exist outside this record.</param>
/// <param name="WebhookUrlHash">Keyed hash of a webhook URL, used only for safe dedupe and troubleshooting.</param>
/// <param name="CreatedAtUtc">When the connection was first created.</param>
/// <param name="UpdatedAtUtc">When the connection was last changed.</param>
/// <param name="ConnectedAtUtc">When the connection became active for privacy-safe ingestion.</param>
/// <param name="UpdatedBy">Admin actor placeholder captured for audit-friendly display.</param>
public sealed record PlatformConnectionRecord(
    string PlatformConnectionId,
    HipPlatformType PlatformType,
    string DisplayName,
    HipPlatformConnectionStatus Status,
    string ExternalWorkspaceId,
    string? ExternalWorkspaceName,
    string? ClientId,
    string? BotUserId,
    bool BotTokenConfigured,
    string? WebhookUrlHash,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? ConnectedAtUtc,
    string UpdatedBy);

/// <summary>
/// Admin API response for a configured platform connection.
/// </summary>
/// <param name="PlatformConnectionId">Stable platform connection id.</param>
/// <param name="PlatformType">Platform name.</param>
/// <param name="DisplayName">Admin-facing display name.</param>
/// <param name="Status">Current connection state.</param>
/// <param name="ExternalWorkspaceId">Privacy-safe workspace id needed for routing platform submissions.</param>
/// <param name="ExternalWorkspaceName">Optional admin-facing workspace name.</param>
/// <param name="ClientId">Optional Discord app client id.</param>
/// <param name="BotUserId">Optional Discord bot user id.</param>
/// <param name="BotTokenConfigured">Whether bot credentials were marked as configured without exposing the token.</param>
/// <param name="WebhookUrlConfigured">Whether a webhook URL hash exists without exposing the raw webhook URL.</param>
/// <param name="InstallUrl">Discord install URL when a client id is available.</param>
/// <param name="UpdatedAtUtc">When the connection was last changed.</param>
/// <param name="ConnectedAtUtc">When the connection became active.</param>
public sealed record PlatformConnectionResponse(
    string PlatformConnectionId,
    string PlatformType,
    string DisplayName,
    string Status,
    string ExternalWorkspaceId,
    string? ExternalWorkspaceName,
    string? ClientId,
    string? BotUserId,
    bool BotTokenConfigured,
    bool WebhookUrlConfigured,
    string? InstallUrl,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? ConnectedAtUtc);

/// <summary>
/// Repository for admin-managed platform connection records.
/// </summary>
public interface IPlatformConnectionRepository
{
    /// <summary>
    /// Saves a privacy-safe platform connection record.
    /// </summary>
    /// <param name="connection">Connection record to persist.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    Task SaveAsync(PlatformConnectionRecord connection, CancellationToken cancellationToken);

    /// <summary>
    /// Reads a platform connection by id.
    /// </summary>
    /// <param name="platformConnectionId">Stable connection id.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Connection record or null when no connection exists.</returns>
    Task<PlatformConnectionRecord?> GetAsync(string platformConnectionId, CancellationToken cancellationToken);

    /// <summary>
    /// Lists saved platform connection records.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Platform connections ordered by recent update.</returns>
    Task<IReadOnlyCollection<PlatformConnectionRecord>> ListAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Coordinates validation and privacy-safe persistence for platform connections.
/// </summary>
public interface IPlatformConnectionService
{
    /// <summary>
    /// Lists configured platform connections.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>Privacy-safe connection responses.</returns>
    Task<IReadOnlyCollection<PlatformConnectionResponse>> ListAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets the Discord connection when configured.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>Discord connection response or null.</returns>
    Task<PlatformConnectionResponse?> GetDiscordAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Connects Discord by saving privacy-safe admin metadata.
    /// </summary>
    /// <param name="request">Discord connection request from an admin-only surface.</param>
    /// <param name="updatedBy">Admin actor placeholder used for audit-friendly display.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Saved privacy-safe connection response.</returns>
    Task<PlatformConnectionResponse> ConnectDiscordAsync(ConnectDiscordPlatformRequest request, string updatedBy, CancellationToken cancellationToken);

    /// <summary>
    /// Disables Discord without deleting the saved connection metadata.
    /// </summary>
    /// <param name="updatedBy">Admin actor placeholder used for audit-friendly display.</param>
    /// <param name="cancellationToken">Token used to cancel persistence work.</param>
    /// <returns>Disabled connection response, or null when Discord was not configured.</returns>
    Task<PlatformConnectionResponse?> DisableDiscordAsync(string updatedBy, CancellationToken cancellationToken);
}

/// <summary>
/// Validates and persists platform connection records without storing raw platform secrets.
/// </summary>
public sealed partial class PlatformConnectionService(
    IPlatformConnectionRepository repository,
    IPrivacyHashingService hashingService,
    TimeProvider timeProvider) : IPlatformConnectionService
{
    /// <summary>
    /// Stable id used for the single Discord connection supported by the MVP.
    /// </summary>
    public const string DiscordConnectionId = "discord";

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<PlatformConnectionResponse>> ListAsync(CancellationToken cancellationToken)
    {
        var records = await repository.ListAsync(cancellationToken);
        return records.Select(ToResponse).ToArray();
    }

    /// <inheritdoc />
    public async Task<PlatformConnectionResponse?> GetDiscordAsync(CancellationToken cancellationToken)
    {
        var record = await repository.GetAsync(DiscordConnectionId, cancellationToken);
        return record is null ? null : ToResponse(record);
    }

    /// <inheritdoc />
    public async Task<PlatformConnectionResponse> ConnectDiscordAsync(
        ConnectDiscordPlatformRequest request,
        string updatedBy,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var guildId = NormalizeSnowflake(request.GuildId, nameof(request.GuildId));
        var clientId = NormalizeOptionalSnowflake(request.ClientId, nameof(request.ClientId));
        var botUserId = NormalizeOptionalSnowflake(request.BotUserId, nameof(request.BotUserId));
        var workspaceName = NormalizeOptionalText(request.GuildName, 100);
        var webhookHash = HashDiscordWebhookUrl(request.WebhookUrl);
        var now = timeProvider.GetUtcNow();
        var existing = await repository.GetAsync(DiscordConnectionId, cancellationToken);

        var record = new PlatformConnectionRecord(
            DiscordConnectionId,
            HipPlatformType.Discord,
            string.IsNullOrWhiteSpace(workspaceName) ? "Discord" : $"Discord - {workspaceName}",
            HipPlatformConnectionStatus.Connected,
            guildId,
            workspaceName,
            clientId,
            botUserId,
            !string.IsNullOrWhiteSpace(request.BotToken) || existing?.BotTokenConfigured == true,
            webhookHash ?? existing?.WebhookUrlHash,
            existing?.CreatedAtUtc ?? now,
            now,
            existing?.ConnectedAtUtc ?? now,
            NormalizeActor(updatedBy));

        await repository.SaveAsync(record, cancellationToken);
        return ToResponse(record);
    }

    /// <inheritdoc />
    public async Task<PlatformConnectionResponse?> DisableDiscordAsync(string updatedBy, CancellationToken cancellationToken)
    {
        var existing = await repository.GetAsync(DiscordConnectionId, cancellationToken);
        if (existing is null)
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        var disabled = existing with
        {
            Status = HipPlatformConnectionStatus.Disabled,
            UpdatedAtUtc = now,
            UpdatedBy = NormalizeActor(updatedBy)
        };

        await repository.SaveAsync(disabled, cancellationToken);
        return ToResponse(disabled);
    }

    /// <summary>
    /// Converts stored connection metadata to an admin-safe response.
    /// </summary>
    /// <param name="record">Stored platform connection record.</param>
    /// <returns>Admin API response with no raw secret material.</returns>
    private static PlatformConnectionResponse ToResponse(PlatformConnectionRecord record) =>
        new(
            record.PlatformConnectionId,
            record.PlatformType.ToString(),
            record.DisplayName,
            record.Status.ToString(),
            record.ExternalWorkspaceId,
            record.ExternalWorkspaceName,
            record.ClientId,
            record.BotUserId,
            record.BotTokenConfigured,
            !string.IsNullOrWhiteSpace(record.WebhookUrlHash),
            BuildDiscordInstallUrl(record.ClientId),
            record.UpdatedAtUtc,
            record.ConnectedAtUtc);

    /// <summary>
    /// Builds a Discord OAuth install URL from a client id without granting broad permissions by default.
    /// </summary>
    /// <param name="clientId">Discord application client id.</param>
    /// <returns>Discord install URL or null when no client id is available.</returns>
    private static string? BuildDiscordInstallUrl(string? clientId) =>
        string.IsNullOrWhiteSpace(clientId)
            ? null
            : $"https://discord.com/oauth2/authorize?client_id={Uri.EscapeDataString(clientId)}&scope=bot%20applications.commands&permissions=0";

    /// <summary>
    /// Normalizes required Discord snowflake ids.
    /// </summary>
    /// <param name="value">Raw id value.</param>
    /// <param name="fieldName">Field name used in validation errors.</param>
    /// <returns>Normalized id.</returns>
    private static string NormalizeSnowflake(string? value, string fieldName)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (!DiscordSnowflakeRegex().IsMatch(normalized))
        {
            throw new ArgumentException($"{fieldName} must be a Discord numeric id.", fieldName);
        }

        return normalized;
    }

    /// <summary>
    /// Normalizes optional Discord snowflake ids.
    /// </summary>
    /// <param name="value">Raw id value.</param>
    /// <param name="fieldName">Field name used in validation errors.</param>
    /// <returns>Normalized id or null.</returns>
    private static string? NormalizeOptionalSnowflake(string? value, string fieldName) =>
        string.IsNullOrWhiteSpace(value) ? null : NormalizeSnowflake(value, fieldName);

    /// <summary>
    /// Normalizes bounded admin text for display. Blazor will still HTML-encode it at render time.
    /// </summary>
    /// <param name="value">Raw text value.</param>
    /// <param name="maxLength">Maximum retained length.</param>
    /// <returns>Trimmed text or null.</returns>
    private static string? NormalizeOptionalText(string? value, int maxLength)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        return normalized.Length <= maxLength ? normalized : normalized[..maxLength];
    }

    /// <summary>
    /// Hashes supported Discord webhook URLs while rejecting non-Discord URLs to avoid storing arbitrary secrets.
    /// </summary>
    /// <param name="webhookUrl">Raw webhook URL supplied by an admin.</param>
    /// <returns>Keyed hash of the webhook URL or null.</returns>
    private string? HashDiscordWebhookUrl(string? webhookUrl)
    {
        if (string.IsNullOrWhiteSpace(webhookUrl))
        {
            return null;
        }

        if (!Uri.TryCreate(webhookUrl.Trim(), UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !IsDiscordHost(uri.Host)
            || !uri.AbsolutePath.StartsWith("/api/webhooks/", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("WebhookUrl must be an HTTPS Discord webhook URL.", nameof(webhookUrl));
        }

        return hashingService.Hash(uri.ToString());
    }

    /// <summary>
    /// Checks whether a host belongs to Discord's webhook domains.
    /// </summary>
    /// <param name="host">URI host.</param>
    /// <returns>True when the host is allowed for Discord webhooks.</returns>
    private static bool IsDiscordHost(string host) =>
        host.Equals("discord.com", StringComparison.OrdinalIgnoreCase)
        || host.Equals("www.discord.com", StringComparison.OrdinalIgnoreCase)
        || host.Equals("discordapp.com", StringComparison.OrdinalIgnoreCase)
        || host.Equals("www.discordapp.com", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Normalizes actor text for admin display without trusting it as authenticated production identity.
    /// </summary>
    /// <param name="updatedBy">Raw actor value from the current admin principal.</param>
    /// <returns>Safe bounded actor label.</returns>
    private static string NormalizeActor(string? updatedBy) =>
        NormalizeOptionalText(updatedBy, 100) ?? "local-admin";

    /// <summary>
    /// Matches Discord snowflake-like numeric ids while rejecting arbitrary strings and script content.
    /// </summary>
    /// <returns>Compiled Discord snowflake regex.</returns>
    [GeneratedRegex("^\\d{17,20}$", RegexOptions.CultureInvariant)]
    private static partial Regex DiscordSnowflakeRegex();
}
