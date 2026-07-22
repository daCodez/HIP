using HIP.Application.SecondLife;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>
/// Proves persistent setup-code lifecycle transitions cannot overwrite one another from stale snapshots.
/// </summary>
[TestFixture]
public sealed class SetupCodeLicenseConcurrencyTests
{
    /// <summary>
    /// Confirms the compatibility device-only settings path cannot mutate a terminal license.
    /// </summary>
    [TestCase(LicenseStatus.Revoked)]
    [TestCase(LicenseStatus.Suspended)]
    public async Task Legacy_device_settings_path_rejects_inactive_persistent_licenses(LicenseStatus status)
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-license-inactive-settings-{status}-{Guid.NewGuid():N}")
            .Options;
        var encryptor = new DevelopmentHipRecordEncryptor();

        await using var context = new HipDbContext(options);
        var service = new EfSetupCodeLicenseService(new HipRecordStore(context, encryptor));
        var created = service.CreateSetupCode(new CreateSetupCodeRequest(1, "test-admin", "Normal"));
        var activation = service.ActivateHud(created.SetupCode, "hud-terminal-device", null, "2.0.0");
        service.SetStatus(created.LicenseId, status);

        var result = service.SaveSettingsForDevice(
            "hud-terminal-device",
            new LicenseHudSettings("Strict", false, false, false));
        var persisted = service.GetLicense(created.LicenseId);

        Assert.Multiple(() =>
        {
            Assert.That(activation.Activated, Is.True);
            Assert.That(result.Saved, Is.False);
            Assert.That(result.Settings, Is.EqualTo(new LicenseHudSettings("Normal", true, true, true)));
            Assert.That(persisted, Is.Not.Null);
            Assert.That(persisted!.Status, Is.EqualTo(status));
            Assert.That(persisted.Settings.ScanMode, Is.EqualTo("Normal"));
        });
    }

    /// <summary>
    /// Reproduces activation reading Pending immediately before an administrator revokes the same license.
    /// </summary>
    [Test]
    public async Task Revocation_wins_when_activation_holds_a_stale_encrypted_snapshot()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-license-revocation-race-{Guid.NewGuid():N}")
            .Options;
        var innerEncryptor = new DevelopmentHipRecordEncryptor();
        CreateSetupCodeResponse created;

        await using (var seedContext = new HipDbContext(options))
        {
            var seedService = new EfSetupCodeLicenseService(new HipRecordStore(seedContext, innerEncryptor));
            created = seedService.CreateSetupCode(new CreateSetupCodeRequest(1, "test-admin", "Normal"));
        }

        using var blockingEncryptor = new BlockingFirstDecryptEncryptor(innerEncryptor);
        await using var activationContext = new HipDbContext(options);
        await using var revocationContext = new HipDbContext(options);
        var activationService = new EfSetupCodeLicenseService(new HipRecordStore(activationContext, blockingEncryptor));
        var revocationService = new EfSetupCodeLicenseService(new HipRecordStore(revocationContext, innerEncryptor));
        var activationTask = Task.Run(() => activationService.ActivateHud(
            created.SetupCode,
            "hud-race-device",
            "avatar-hash",
            "2.0.0"));

        await blockingEncryptor.WaitUntilSnapshotIsReadAsync();
        var revoked = revocationService.SetStatus(created.LicenseId, LicenseStatus.Revoked);
        blockingEncryptor.Release();
        var activation = await activationTask;

        await using var verificationContext = new HipDbContext(options);
        var verificationStore = new HipRecordStore(verificationContext, innerEncryptor);
        var stored = await verificationStore.GetEncryptedVersionedAsync<SetupCodeLicense>(
            "setup-code-licenses",
            created.LicenseId,
            CancellationToken.None);
        var storedRow = await verificationContext.Records.AsNoTracking()
            .SingleAsync(record =>
                record.Partition == "setup-code-licenses" &&
                record.Id == created.LicenseId);

        Assert.Multiple(() =>
        {
            Assert.That(revoked, Is.Not.Null);
            Assert.That(revoked!.Status, Is.EqualTo(LicenseStatus.Revoked));
            Assert.That(activation.Activated, Is.False);
            Assert.That(activation.LicenseStatus, Is.EqualTo(LicenseStatus.Revoked));
            Assert.That(stored, Is.Not.Null);
            Assert.That(stored!.Value.Record.Status, Is.EqualTo(LicenseStatus.Revoked));
            Assert.That(stored.Value.Record.DeviceIds, Is.Empty);
            Assert.That(stored.Value.Record.Version, Is.EqualTo(2));
            Assert.That(stored.Value.AggregateVersion, Is.EqualTo(2));
            Assert.That(storedRow.AggregateVersion, Is.EqualTo(2));
            Assert.That(innerEncryptor.IsProtectedPayload(storedRow.Json), Is.True);
        });
    }

    /// <summary>
    /// Pauses the first decrypt after the database query has captured its encrypted snapshot.
    /// </summary>
    private sealed class BlockingFirstDecryptEncryptor(IHipRecordEncryptor inner) : IHipRecordEncryptor, IDisposable
    {
        private readonly TaskCompletionSource snapshotRead =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ManualResetEventSlim release = new(false);
        private int blocked;

        public string Protect(string plaintextJson) => inner.Protect(plaintextJson);

        public string Unprotect(string storedPayload)
        {
            var plaintext = inner.Unprotect(storedPayload);
            if (Interlocked.CompareExchange(ref blocked, 1, 0) == 0)
            {
                snapshotRead.TrySetResult();
                if (!release.Wait(TimeSpan.FromSeconds(10)))
                {
                    throw new TimeoutException("The license concurrency test did not release the captured snapshot.");
                }
            }

            return plaintext;
        }

        public bool IsProtectedPayload(string storedPayload) => inner.IsProtectedPayload(storedPayload);

        public Task WaitUntilSnapshotIsReadAsync() =>
            snapshotRead.Task.WaitAsync(TimeSpan.FromSeconds(10));

        public void Release() => release.Set();

        public void Dispose() => release.Dispose();
    }
}
