using HIP.Application.SecondLife;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Locks durable setup-code expiry and one-time default consumption.</summary>
public sealed class SetupCodeLicenseExpiryPersistenceTests
{
    [Test]
    public async Task Expiry_and_consumption_survive_repository_recreation_without_plaintext_rows()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-license-expiry-{Guid.NewGuid():N}")
            .Options;
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 7, 21, 12, 0, 0, TimeSpan.Zero));
        await using var context = new HipDbContext(options);
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());
        var service = new EfSetupCodeLicenseService(store, clock);
        var consumedCode = service.CreateSetupCode(new CreateSetupCodeRequest(1, "actor", "Normal", 24));
        var expiringCode = service.CreateSetupCode(new CreateSetupCodeRequest(1, "actor", "Normal", 1));

        Assert.That(service.ActivateHud(consumedCode.SetupCode, "hud-one", null, "1.0").Activated, Is.True);
        clock.UtcNow = expiringCode.SetupCodeExpiresAtUtc!.Value;
        Assert.That(service.ActivateHud(expiringCode.SetupCode, "hud-expired", null, "1.0").Activated, Is.False);

        var recreated = new EfSetupCodeLicenseService(store, clock);
        var consumed = recreated.GetLicense(consumedCode.LicenseId);
        var expired = recreated.GetLicense(expiringCode.LicenseId);
        var rows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(consumed!.SetupCodeConsumedAtUtc, Is.Not.Null);
            Assert.That(expired!.Status, Is.EqualTo(LicenseStatus.Expired));
            Assert.That(rows.All(row => !row.Json.Contains(consumedCode.SetupCode, StringComparison.Ordinal)), Is.True);
            Assert.That(rows.All(row => !row.Json.Contains(expiringCode.SetupCode, StringComparison.Ordinal)), Is.True);
        });
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
