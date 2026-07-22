using HIP.Application.Identity;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;

namespace HIP.Tests.Protocol;

/// <summary>
/// Proves signing-key state and its audit evidence share one compare-and-swap commit boundary.
/// </summary>
public sealed class SigningKeyLifecycleAtomicAuditTests
{
    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 18, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Stale_compare_and_swap_writes_zero_audit_facts()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var registered = SigningKeyRing.Create("hip:domain:example")
            .RegisterActiveKey("key-1", "ML-DSA-65", "public-key-1", InitialTime);
        var registrationAudit = CreateAudit("audit-register", "SigningKeyActivated", "key-1");
        Assert.That(
            await repository.TrySaveAsync(
                new SigningKeyLifecycleTransitionBatch(registered, 0, [registrationAudit]),
                CancellationToken.None),
            Is.True);

        var winningRing = registered.Rotate(
            "key-1",
            "key-2",
            "ML-DSA-65",
            "public-key-2",
            InitialTime.AddMinutes(1));
        Assert.That(
            await repository.TrySaveAsync(
                new SigningKeyLifecycleTransitionBatch(
                    winningRing,
                    registered.Version,
                    [
                        CreateAudit("audit-rotate-old", "SigningKeyRotationStarted", "key-1"),
                        CreateAudit("audit-rotate-new", "SigningKeyActivated", "key-2")
                    ]),
                CancellationToken.None),
            Is.True);

        var staleRing = registered.Rotate(
            "key-1",
            "key-3",
            "ML-DSA-65",
            "public-key-3",
            InitialTime.AddMinutes(2));
        var staleSaved = await repository.TrySaveAsync(
            new SigningKeyLifecycleTransitionBatch(
                staleRing,
                registered.Version,
                [
                    CreateAudit("audit-stale-old", "SigningKeyRotationStarted", "key-1"),
                    CreateAudit("audit-stale-new", "SigningKeyActivated", "key-3")
                ]),
            CancellationToken.None);

        var stored = await repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var audits = await repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(staleSaved, Is.False);
            Assert.That(stored, Is.EqualTo(winningRing));
            Assert.That(audits.Select(entry => entry.AuditLogId),
                Is.EquivalentTo(new[] { "audit-register", "audit-rotate-old", "audit-rotate-new" }));
            Assert.That(audits, Has.None.Matches<AuditLogEntry>(entry => entry.AuditLogId.StartsWith("audit-stale", StringComparison.Ordinal)));
        });
    }

    [Test]
    public async Task Audit_collision_rejects_the_entire_rotation_commit()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var registered = SigningKeyRing.Create("hip:domain:example")
            .RegisterActiveKey("key-1", "ML-DSA-65", "public-key-1", InitialTime);
        var registrationAudit = CreateAudit("audit-existing", "SigningKeyActivated", "key-1");
        Assert.That(
            await repository.TrySaveAsync(
                new SigningKeyLifecycleTransitionBatch(registered, 0, [registrationAudit]),
                CancellationToken.None),
            Is.True);

        var rotation = registered.Rotate(
            "key-1",
            "key-2",
            "ML-DSA-65",
            "public-key-2",
            InitialTime.AddMinutes(1));

        var saved = await repository.TrySaveAsync(
            new SigningKeyLifecycleTransitionBatch(
                rotation,
                registered.Version,
                [
                    CreateAudit("audit-new", "SigningKeyRotationStarted", "key-1"),
                    CreateAudit("audit-existing", "SigningKeyActivated", "key-2")
                ]),
            CancellationToken.None);

        var stored = await repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var audits = await repository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.False);
            Assert.That(stored, Is.EqualTo(registered));
            Assert.That(audits, Has.Count.EqualTo(1));
            Assert.That(audits.Single().AuditLogId, Is.EqualTo("audit-existing"));
        });
    }

    private static AuditLogEntry CreateAudit(string id, string action, string keyId) =>
        new(
            id,
            "operator-1",
            action,
            TargetType.DeviceKey,
            $"hip:domain:example:{keyId}",
            "Privacy-safe lifecycle transition",
            InitialTime,
            new Dictionary<string, string>
            {
                ["identityId"] = "hip:domain:example",
                ["keyId"] = keyId
            },
            AuditSeverity.Medium);
}
