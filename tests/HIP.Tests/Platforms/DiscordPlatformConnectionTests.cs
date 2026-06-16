using HIP.Application.Platforms;
using HIP.Application.Reporting;

namespace HIP.Tests.Platforms;

/// <summary>
/// Verifies Discord platform connection behavior stays privacy-safe while becoming usable by admins.
/// </summary>
public sealed class DiscordPlatformConnectionTests
{
    /// <summary>
    /// Verifies Discord connection metadata is saved without raw webhook URLs or bot tokens.
    /// </summary>
    [Test]
    public async Task Connect_discord_saves_privacy_safe_metadata()
    {
        var repository = new InMemoryPlatformConnectionRepository();
        var service = new PlatformConnectionService(repository, new Sha256PrivacyHashingService(), TimeProvider.System);
        var request = new ConnectDiscordPlatformRequest(
            "123456789012345678",
            "HIP Test Server",
            "223456789012345678",
            "323456789012345678",
            "https://discord.com/api/webhooks/123/secret",
            "raw-bot-token");

        var response = await service.ConnectDiscordAsync(request, "admin-test", CancellationToken.None);
        var stored = await repository.GetAsync(PlatformConnectionService.DiscordConnectionId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(response.Status, Is.EqualTo(nameof(HipPlatformConnectionStatus.Connected)));
            Assert.That(response.BotTokenConfigured, Is.EqualTo(true));
            Assert.That(response.WebhookUrlConfigured, Is.EqualTo(true));
            Assert.That(stored?.WebhookUrlHash, Does.StartWith("sha256:"));
            Assert.That(stored?.WebhookUrlHash, Does.Not.Contain("discord.com/api/webhooks"));
            Assert.That(stored?.ToString(), Does.Not.Contain("raw-bot-token"));
            Assert.That(response.InstallUrl, Does.Contain("discord.com/oauth2/authorize"));
        });
    }

    /// <summary>
    /// Verifies invalid Discord guild ids are rejected before persistence.
    /// </summary>
    [Test]
    public void Connect_discord_rejects_invalid_guild_id()
    {
        var service = new PlatformConnectionService(
            new InMemoryPlatformConnectionRepository(),
            new Sha256PrivacyHashingService(),
            TimeProvider.System);
        var request = new ConnectDiscordPlatformRequest("not-a-guild-id", null, null, null, null, null);

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.ConnectDiscordAsync(request, "admin-test", CancellationToken.None));

        Assert.That(exception?.Message, Does.Contain("GuildId must be a Discord numeric id"));
    }

    /// <summary>
    /// Verifies disabling Discord preserves the record and changes only its state.
    /// </summary>
    [Test]
    public async Task Disable_discord_preserves_connection_metadata()
    {
        var repository = new InMemoryPlatformConnectionRepository();
        var service = new PlatformConnectionService(repository, new Sha256PrivacyHashingService(), TimeProvider.System);
        await service.ConnectDiscordAsync(
            new ConnectDiscordPlatformRequest("123456789012345678", "HIP Test Server", null, null, null, null),
            "admin-test",
            CancellationToken.None);

        var disabled = await service.DisableDiscordAsync("admin-test", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(disabled?.Status, Is.EqualTo(nameof(HipPlatformConnectionStatus.Disabled)));
            Assert.That(disabled?.ExternalWorkspaceId, Is.EqualTo("123456789012345678"));
        });
    }

    /// <summary>
    /// Small in-memory repository used by focused platform connection service tests.
    /// </summary>
    private sealed class InMemoryPlatformConnectionRepository : IPlatformConnectionRepository
    {
        private readonly Dictionary<string, PlatformConnectionRecord> records = new(StringComparer.OrdinalIgnoreCase);

        /// <inheritdoc />
        public Task SaveAsync(PlatformConnectionRecord connection, CancellationToken cancellationToken)
        {
            records[connection.PlatformConnectionId] = connection;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<PlatformConnectionRecord?> GetAsync(string platformConnectionId, CancellationToken cancellationToken)
        {
            records.TryGetValue(platformConnectionId, out var record);
            return Task.FromResult(record);
        }

        /// <inheritdoc />
        public Task<IReadOnlyCollection<PlatformConnectionRecord>> ListAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<PlatformConnectionRecord>>(records.Values.ToArray());
    }
}
