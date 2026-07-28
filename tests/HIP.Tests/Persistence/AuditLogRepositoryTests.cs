using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

public sealed class AuditLogRepositoryTests
{
    [Test]
    public async Task Known_integrity_repair_replaces_the_original_and_adds_the_attestation_atomically()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-audit-repair-{Guid.NewGuid():N}")
            .Options;
        await using var context = new HipDbContext(options);
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());
        var repository = new EfAuditLogRepository(store);
        var service = new AuditLogService(repository);
        var sealedEntry = service.CreateEntry(
            $"owner-hmac-sha256-v1:{new string('a', 64)}",
            "ConsumerDevice.Registered",
            TargetType.DeviceKey,
            "device-1",
            "A consumer device completed proof-of-possession registration.",
            AuditSeverity.Medium,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["keyAlgorithm"] = "ES256",
                ["publicKeyFingerprint"] = $"sha256:{new string('b', 43)}",
                ["trustState"] = "ProofOfPossessionVerified",
                ["revocationState"] = "Active"
            },
            actorRole: "Consumer");
        var affected = sealedEntry with
        {
            CreatedAtUtc = sealedEntry.CreatedAtUtc.AddMinutes(-5)
        };
        await repository.SaveAsync(affected, CancellationToken.None);

        var entries = await service.ListAsync(CancellationToken.None);
        var repaired = await store.GetEncryptedVersionedAsync<AuditLogEntry>(
            "audit-log",
            affected.AuditLogId,
            CancellationToken.None);
        var attestation = entries.Single(entry =>
            entry.Action == "AuditIntegrity.LegacyDeviceTimestampResealed");
        var storedAttestation = await store.GetEncryptedVersionedAsync<AuditLogEntry>(
            "audit-log",
            attestation.AuditLogId,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(entries, Has.Count.EqualTo(2));
            Assert.That(entries.All(AuditLogIntegrity.Verify), Is.True);
            Assert.That(repaired, Is.Not.Null);
            Assert.That(repaired!.Value.AggregateVersion, Is.EqualTo(2));
            Assert.That(repaired.Value.Record.CreatedAtUtc, Is.EqualTo(affected.CreatedAtUtc));
            Assert.That(storedAttestation, Is.Not.Null);
            Assert.That(storedAttestation!.Value.AggregateVersion, Is.EqualTo(0));
        });

        var secondRead = await service.ListAsync(CancellationToken.None);
        Assert.That(secondRead, Has.Count.EqualTo(2));
    }
}
