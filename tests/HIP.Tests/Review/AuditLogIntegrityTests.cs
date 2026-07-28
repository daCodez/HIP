using System.Security.Cryptography;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Tests.Review;

public sealed class AuditLogIntegrityTests
{
    [Test]
    public void New_audit_entries_are_sealed_and_tampering_is_detected()
    {
        var service = new AuditLogService(new InMemoryAuditLogRepository());
        var entry = service.CreateEntry("actor", "ChangedSettings", TargetType.Rule, "rule-1", "Changed safe settings.", AuditSeverity.Medium);

        Assert.Multiple(() =>
        {
            Assert.That(entry.IntegrityVersion, Is.EqualTo(AuditLogIntegrity.CurrentVersion));
            Assert.That(entry.IntegrityHash, Has.Length.EqualTo(64));
            Assert.That(AuditLogIntegrity.Verify(entry), Is.True);
            Assert.That(AuditLogIntegrity.Verify(entry with { Summary = "Tampered summary." }), Is.False);
            Assert.That(AuditLogIntegrity.Verify(entry with { IntegrityHash = null! }), Is.False);
        });
    }

    [Test]
    public void Repository_rejects_overwrite_of_existing_audit_identifier()
    {
        var repository = new InMemoryAuditLogRepository();
        var service = new AuditLogService(repository);
        var entry = service.CreateEntry("actor", "Action", TargetType.Rule, "rule-1", "Summary.", AuditSeverity.Low);
        repository.SaveAsync(entry, CancellationToken.None).GetAwaiter().GetResult();

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.SaveAsync(entry with { Summary = "Overwrite." }, CancellationToken.None));
    }

    [Test]
    public void Listing_rejects_modified_sealed_entry_but_accepts_legacy_unsealed_entry()
    {
        var repository = new InMemoryAuditLogRepository();
        var service = new AuditLogService(repository);
        var sealedEntry = service.CreateEntry("actor", "Action", TargetType.Rule, "rule-1", "Summary.", AuditSeverity.Low);
        repository.SaveAsync(sealedEntry with { TargetId = "tampered" }, CancellationToken.None).GetAwaiter().GetResult();
        Assert.ThrowsAsync<InvalidOperationException>(() => service.ListAsync(CancellationToken.None));

        var legacyRepository = new InMemoryAuditLogRepository();
        legacyRepository.SaveAsync(new AuditLogEntry(
            "legacy", "actor", "Action", TargetType.Rule, "rule-1", "Legacy.", DateTimeOffset.UtcNow,
            new Dictionary<string, string>(), AuditSeverity.Low), CancellationToken.None).GetAwaiter().GetResult();
        Assert.That(new AuditLogService(legacyRepository).List(), Has.Count.EqualTo(1));
    }

    [Test]
    public async Task Export_is_ordered_and_has_a_verifiable_checksum()
    {
        var service = new AuditLogService(new InMemoryAuditLogRepository());
        service.Write("actor", "First", TargetType.Rule, "rule-1", "First.", AuditSeverity.Low);
        service.Write("actor", "Second", TargetType.Rule, "rule-2", "Second.", AuditSeverity.Medium);

        var export = await new AuditExportService(service).ExportAsync(CancellationToken.None);
        var expected = Convert.ToHexString(SHA256.HashData(export.JsonLines)).ToLowerInvariant();

        Assert.Multiple(() =>
        {
            Assert.That(export.EntryCount, Is.EqualTo(2));
            Assert.That(export.Sha256, Is.EqualTo(expected));
            Assert.That(export.EarliestAtUtc, Is.Not.Null);
            Assert.That(export.LatestAtUtc, Is.Not.Null);
            Assert.That(export.EarliestAtUtc!.Value,
                Is.LessThanOrEqualTo(export.LatestAtUtc!.Value));
        });
    }

    [Test]
    public async Task Listing_atomically_repairs_the_known_device_timestamp_seal_defect_and_attests_it()
    {
        var repository = new InMemoryAuditLogRepository();
        var service = new AuditLogService(repository);
        var original = service.CreateEntry(
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
        var affected = original with { CreatedAtUtc = original.CreatedAtUtc.AddMinutes(-5) };
        await repository.SaveAsync(affected, CancellationToken.None);

        var entries = await service.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(entries, Has.Count.EqualTo(2));
            Assert.That(entries.All(AuditLogIntegrity.Verify), Is.True);
            var repaired = entries.Single(entry => entry.AuditLogId == affected.AuditLogId);
            Assert.That(repaired.CreatedAtUtc, Is.EqualTo(affected.CreatedAtUtc));
            var attestation = entries.Single(entry =>
                entry.Action == "AuditIntegrity.LegacyDeviceTimestampResealed");
            Assert.That(attestation.TargetId, Is.EqualTo(affected.TargetId));
            Assert.That(attestation.Metadata["repairedAuditLogId"], Is.EqualTo(affected.AuditLogId));
            Assert.That(attestation.Metadata["defectVersion"],
                Is.EqualTo("device-created-at-post-seal-v1"));
        });
    }
}
