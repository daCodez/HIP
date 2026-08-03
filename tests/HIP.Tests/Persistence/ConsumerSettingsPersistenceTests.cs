using HIP.Application.Consumer;
using HIP.Application.Reporting;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

[TestFixture]
public sealed class ConsumerSettingsPersistenceTests
{
    [Test]
    public async Task Settings_are_encrypted_owner_scoped_and_survive_service_recreation()
    {
        await using var context = new HipDbContext(
            new DbContextOptionsBuilder<HipDbContext>()
                .UseInMemoryDatabase($"consumer-settings-{Guid.NewGuid():N}")
                .Options);
        var repository = new EfConsumerSettingsRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var first = Service(repository);

        var saved = await first.SaveSettingsAsync(
            "consumer-A",
            new ConsumerSettings(
                false,
                true,
                true,
                "Strict",
                new Dictionary<string, ConsumerBadgeConfiguration>(StringComparer.Ordinal)
                {
                    ["example.com"] = new("dark", "bottom-left", 82)
                }),
            CancellationToken.None);
        var recreated = Service(repository);
        var owner = await recreated.GetSettingsAsync("consumer-A", CancellationToken.None);
        var other = await recreated.GetSettingsAsync("consumer-B", CancellationToken.None);
        var row = await context.Records.AsNoTracking()
            .SingleAsync(record => record.Partition == "consumer-settings");

        Assert.Multiple(() =>
        {
            Assert.That(saved.Saved, Is.True);
            Assert.That(owner.ScanMode, Is.EqualTo("Strict"));
            Assert.That(owner.EnablePopupAlerts, Is.False);
            Assert.That(owner.BadgeConfigurations!["example.com"].Theme, Is.EqualTo("dark"));
            Assert.That(owner.BadgeConfigurations["example.com"].Position, Is.EqualTo("bottom-left"));
            Assert.That(owner.BadgeConfigurations["example.com"].Opacity, Is.EqualTo(82));
            Assert.That(other.BadgeConfigurations, Is.Empty);
            Assert.That(other.ScanMode, Is.EqualTo("Normal"));
            Assert.That(row.Id, Does.StartWith("sha256:"));
            Assert.That(row.Id, Does.Not.Contain("consumer-A"));
            Assert.That(new DevelopmentHipRecordEncryptor().IsProtectedPayload(row.Json), Is.True);
            Assert.That(row.Json, Does.Not.Contain("consumer-A"));
        });
    }

    private static ConsumerPortalService Service(IConsumerSettingsRepository repository) => new(
        riskFindingRepository: null!,
        appealService: null!,
        privacyHashingService: new Sha256PrivacyHashingService(),
        deviceRegistrationService: null!,
        appealRepository: null!,
        settingsRepository: repository);
}
