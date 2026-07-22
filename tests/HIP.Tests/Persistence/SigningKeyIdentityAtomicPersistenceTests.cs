using HIP.Application.Identity;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace HIP.Tests.Persistence;

/// <summary>
/// Proves initial identity registration uses one encrypted persistence boundary for identity, key ring, and audit.
/// </summary>
public sealed class SigningKeyIdentityAtomicPersistenceTests
{
    private const string IdentityPartition = "identity";
    private const string RingPartition = "signing-key-ring";
    private const string AuditPartition = "audit-log";
    private const string IdentityId = "hip:person:atomic-registration";
    private static readonly DateTimeOffset CreatedAtUtc =
        new(2026, 7, 18, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Initial_registration_encrypts_heterogeneous_records_with_one_save()
    {
        var saveCounter = new SaveChangesCounter();
        await using var context = CreateContext(saveCounter);
        var encryptor = new DevelopmentHipRecordEncryptor();
        var store = new HipRecordStore(context, encryptor);
        var repository = new EfSigningKeyLifecycleRepository(store);
        var batch = CreateBatch();

        var saved = await repository.TryRegisterIdentityAsync(batch, CancellationToken.None);

        var restoredIdentity = await repository.GetRegisteredIdentityAsync(
            IdentityId,
            CancellationToken.None);
        var restoredRing = await repository.GetAsync(IdentityId, CancellationToken.None);
        var audits = await store.ListAsync<AuditLogEntry>(AuditPartition, CancellationToken.None);
        var storedRows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.True);
            Assert.That(saveCounter.AsyncSaveCount, Is.EqualTo(1));
            Assert.That(restoredIdentity, Is.EqualTo(batch.Identity));
            AssertSigningKeyRingEquivalent(batch.LifecycleTransition.KeyRing, restoredRing);
            Assert.That(audits.Select(entry => entry.AuditLogId), Is.EquivalentTo(new[] { "audit-initial" }));
            Assert.That(storedRows, Has.Length.EqualTo(3));
            Assert.That(storedRows, Has.All.Matches<HipDbRecord>(row => encryptor.IsProtectedPayload(row.Json)));
            Assert.That(
                storedRows.Single(row => row.Partition == RingPartition).AggregateVersion,
                Is.EqualTo(1));
            Assert.That(
                storedRows.Where(row => row.Partition != RingPartition),
                Has.All.Matches<HipDbRecord>(row => row.AggregateVersion == 0));
        });
    }

    [Test]
    public async Task Identity_collision_rejects_ring_and_audit_without_overwriting_existing_identity()
    {
        await using var context = CreateContext();
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());
        var repository = new EfSigningKeyLifecycleRepository(store);
        var batch = CreateBatch();
        var existingIdentity = batch.Identity with { DisplayName = "Existing identity" };
        await store.SaveAsync(
            IdentityPartition,
            IdentityId,
            existingIdentity,
            CancellationToken.None);

        var saved = await repository.TryRegisterIdentityAsync(batch, CancellationToken.None);

        var restoredIdentity = await repository.GetRegisteredIdentityAsync(
            IdentityId,
            CancellationToken.None);
        var restoredRing = await repository.GetAsync(IdentityId, CancellationToken.None);
        var audits = await store.ListAsync<AuditLogEntry>(AuditPartition, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.False);
            Assert.That(restoredIdentity, Is.EqualTo(existingIdentity));
            Assert.That(restoredRing, Is.Null);
            Assert.That(audits, Is.Empty);
            Assert.That(context.Records.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Audit_collision_rejects_identity_and_ring_without_overwriting_existing_audit()
    {
        await using var context = CreateContext();
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());
        var repository = new EfSigningKeyLifecycleRepository(store);
        var batch = CreateBatch();
        var existingAudit = CreateAudit("audit-initial", "ExistingAuditFact");
        await store.SaveAsync(
            AuditPartition,
            existingAudit.AuditLogId,
            existingAudit,
            CancellationToken.None);

        var saved = await repository.TryRegisterIdentityAsync(batch, CancellationToken.None);

        var restoredIdentity = await repository.GetRegisteredIdentityAsync(
            IdentityId,
            CancellationToken.None);
        var restoredRing = await repository.GetAsync(IdentityId, CancellationToken.None);
        var audits = await store.ListAsync<AuditLogEntry>(AuditPartition, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.False);
            Assert.That(restoredIdentity, Is.Null);
            Assert.That(restoredRing, Is.Null);
            Assert.That(audits, Has.Count.EqualTo(1));
            AssertAuditEquivalent(existingAudit, audits.Single());
            Assert.That(context.Records.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Registered_identity_read_rejects_ciphertext_bound_to_another_identity()
    {
        await using var context = CreateContext();
        var store = new HipRecordStore(context, new DevelopmentHipRecordEncryptor());
        var repository = new EfSigningKeyLifecycleRepository(store);
        var copiedIdentity = CreateBatch().Identity with { IdentityId = "hip:person:other" };
        await store.SaveAsync(
            IdentityPartition,
            IdentityId,
            copiedIdentity,
            CancellationToken.None);

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.GetRegisteredIdentityAsync(
            IdentityId,
            CancellationToken.None));
    }

    private static IdentitySigningKeyRegistrationBatch CreateBatch()
    {
        var identity = new HipIdentity(
            IdentityId,
            IdentitySubjectType.Person,
            "Atomic registration",
            "public-key-1",
            "ML-DSA-65",
            VerificationStatus.Pending,
            CreatedAtUtc,
            "atomic-registration");
        var ring = SigningKeyRing.Create(IdentityId)
            .RegisterActiveKey(
                "default",
                identity.KeyAlgorithm,
                identity.PublicKey,
                "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                CreatedAtUtc);
        var transition = new SigningKeyLifecycleTransitionBatch(
            ring,
            expectedVersion: 0,
            [CreateAudit("audit-initial", "SigningKeyActivated")]);
        return new IdentitySigningKeyRegistrationBatch(identity, transition);
    }

    private static AuditLogEntry CreateAudit(string auditId, string action) =>
        new(
            auditId,
            "system:test",
            action,
            TargetType.DeviceKey,
            $"{IdentityId}:default",
            "Privacy-safe initial registration test",
            CreatedAtUtc,
            new Dictionary<string, string>
            {
                ["identityId"] = IdentityId,
                ["keyId"] = "default"
            },
            AuditSeverity.Medium);

    private static void AssertSigningKeyRingEquivalent(
        SigningKeyRing expected,
        SigningKeyRing? actual)
    {
        Assert.That(actual, Is.Not.Null);
        Assert.Multiple(() =>
        {
            Assert.That(actual!.IdentityId, Is.EqualTo(expected.IdentityId));
            Assert.That(actual.Version, Is.EqualTo(expected.Version));
            Assert.That(
                actual.Keys.Select(ToComparableKey),
                Is.EqualTo(expected.Keys.Select(ToComparableKey)));
        });

        static object ToComparableKey(ManagedSigningKey key) => new
        {
            key.KeyId,
            key.Algorithm,
            key.PublicKey,
            key.PublicKeyFingerprint,
            key.Status,
            key.ReplacementKeyId,
            key.ActivatedAtUtc,
            key.StatusChangedAtUtc,
            key.RetiringAtUtc,
            key.RetiredAtUtc,
            key.RevokedAtUtc,
            key.Version
        };
    }

    private static void AssertAuditEquivalent(AuditLogEntry expected, AuditLogEntry actual)
    {
        Assert.Multiple(() =>
        {
            Assert.That(actual.AuditLogId, Is.EqualTo(expected.AuditLogId));
            Assert.That(actual.ActorId, Is.EqualTo(expected.ActorId));
            Assert.That(actual.Action, Is.EqualTo(expected.Action));
            Assert.That(actual.TargetType, Is.EqualTo(expected.TargetType));
            Assert.That(actual.TargetId, Is.EqualTo(expected.TargetId));
            Assert.That(actual.Summary, Is.EqualTo(expected.Summary));
            Assert.That(actual.CreatedAtUtc, Is.EqualTo(expected.CreatedAtUtc));
            Assert.That(actual.Metadata, Is.EquivalentTo(expected.Metadata));
            Assert.That(actual.Severity, Is.EqualTo(expected.Severity));
            Assert.That(actual.ActorRole, Is.EqualTo(expected.ActorRole));
            Assert.That(actual.BeforeMetadata, Is.EquivalentTo(expected.BeforeMetadata));
            Assert.That(actual.AfterMetadata, Is.EquivalentTo(expected.AfterMetadata));
            Assert.That(actual.CorrelationId, Is.EqualTo(expected.CorrelationId));
        });
    }

    private static HipDbContext CreateContext(SaveChangesInterceptor? interceptor = null)
    {
        var builder = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-atomic-registration-{Guid.NewGuid():N}");
        if (interceptor is not null)
        {
            builder.AddInterceptors(interceptor);
        }

        return new HipDbContext(builder.Options);
    }

    private sealed class SaveChangesCounter : SaveChangesInterceptor
    {
        public int AsyncSaveCount { get; private set; }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            AsyncSaveCount++;
            return ValueTask.FromResult(result);
        }
    }
}
