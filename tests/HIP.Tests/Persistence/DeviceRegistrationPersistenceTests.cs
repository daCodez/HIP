using System.Text.Json;
using System.Text.Json.Serialization;
using HIP.Application.Devices;
using HIP.Domain.Audit;
using HIP.Domain.Devices;
using HIP.Domain.Review;
using HIP.Infrastructure;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP device registration uses encrypted, atomic, owner-bound persistence.</summary>
public sealed class DeviceRegistrationPersistenceTests
{
    private const string AggregatePartition = "device-registration-owner";
    private const string DeviceBindingPartition = "device-registration-device-binding";
    private const string KeyBindingPartition = "device-registration-key-binding";
    private const string AuditPartition = "audit-log";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Aggregate_bindings_and_audit_commit_as_encrypted_related_records()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var store = new HipRecordStore(context, encryptor);
        var repository = new EfDeviceRegistrationRepository(store);
        var (aggregate, result) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "device-a");
        var restored = await repository.GetAsync(aggregate.OwnerScopeId, CancellationToken.None);
        var rows = await context.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(restored, Is.Not.Null);
            Assert.That(restored!.OwnerScopeId, Is.EqualTo(aggregate.OwnerScopeId));
            Assert.That(restored.Version, Is.EqualTo(aggregate.Version));
            Assert.That(restored.Devices.Single(), Is.EqualTo(aggregate.Devices.Single()));
            Assert.That(rows, Has.Length.EqualTo(5));
            Assert.That(
                rows.Single(row => row.Partition == AggregatePartition).AggregateVersion,
                Is.EqualTo(aggregate.Version));
            Assert.That(rows.Select(row => row.Partition), Is.EquivalentTo(new[]
            {
                AggregatePartition,
                DeviceBindingPartition,
                KeyBindingPartition,
                AuditPartition,
                AuditPartition
            }));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row => encryptor.IsProtectedPayload(row.Json)));
        });
    }

    [TestCase(0)]
    [TestCase(1)]
    public async Task Newly_added_device_requires_both_immutable_bindings(int bindingCount)
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var ownerScope = OwnerScope('a');
        var device = RegisteredAggregate(ownerScope, "dev_A", Fingerprint('A'), version: 0)
            .Devices.Single();
        var challenged = await IssueChallengeAsync(
            repository,
            ownerScope,
            current: null,
            device,
            "incomplete-bindings");
        var aggregate = CompleteRegistration(challenged, device);
        var requestedBindings = Bindings(device, aggregate.OwnerScopeId)
            .Take(bindingCount)
            .ToArray();

        Assert.ThrowsAsync<ArgumentException>(() => repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                aggregate,
                ExpectedVersion: challenged.Version,
                requestedBindings,
                [Audit("audit-incomplete-bindings", aggregate.OwnerScopeId, "dev_A")]),
            CancellationToken.None));
        Assert.That(context.Records.AsNoTracking().Count(), Is.EqualTo(2));
    }

    [Test]
    public async Task Transition_without_a_new_device_rejects_replayed_bindings()
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var (original, created) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "created-for-replay");
        var unchangedDevice = original with { Version = original.Version + 1 };

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.ThrowsAsync<ArgumentException>(() => repository.TrySaveAsync(
                new DeviceRegistrationTransitionBatch(
                    unchangedDevice,
                    ExpectedVersion: original.Version,
                    Bindings(unchangedDevice.Devices.Single(), unchangedDevice.OwnerScopeId),
                    [Audit("audit-replayed-bindings", unchangedDevice.OwnerScopeId, "dev_A")]),
                CancellationToken.None));
            Assert.That(context.Records.AsNoTracking().Count(), Is.EqualTo(5));
        });
    }

    [Test]
    public async Task Existing_device_cannot_change_key_identity_without_new_global_bindings()
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var (original, created) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "created-for-key-mutation");
        var mutated = original with
        {
            Version = original.Version + 1,
            Devices = [original.Devices.Single() with
            {
                PublicKey = "different-public-key",
                PublicKeyFingerprint = Fingerprint('B')
            }]
        };

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.ThrowsAsync<ArgumentException>(() => repository.TrySaveAsync(
                new DeviceRegistrationTransitionBatch(
                    mutated,
                    ExpectedVersion: original.Version,
                    [],
                    [Audit("audit-key-mutation", mutated.OwnerScopeId, "dev_A")]),
                CancellationToken.None));
        });
    }

    [Test]
    public async Task Active_device_cannot_be_pruned_from_the_owner_aggregate()
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var (original, created) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "created-for-active-prune");
        var pruned = original with { Version = original.Version + 1, Devices = [] };

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.ThrowsAsync<ArgumentException>(() => repository.TrySaveAsync(
                new DeviceRegistrationTransitionBatch(
                    pruned,
                    ExpectedVersion: original.Version,
                    [],
                    [Audit("audit-active-prune", pruned.OwnerScopeId, "dev_A")]),
                CancellationToken.None));
        });
    }

    [Test]
    public async Task Revoked_device_can_be_pruned_when_a_correctly_bound_replacement_is_added()
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var (original, created) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "created-for-replacement");
        var revoked = original with
        {
            Version = original.Version + 1,
            Devices = [original.Devices.Single() with
            {
                RevocationState = DeviceRevocationState.Revoked,
                RevokedAtUtc = Now.AddMinutes(1)
            }]
        };
        var revokedResult = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                revoked,
                ExpectedVersion: original.Version,
                [],
                [Audit("audit-revoked-for-replacement", original.OwnerScopeId, "dev_A")]),
            CancellationToken.None);
        var (replacement, replacementResult) = await RegisterDeviceAsync(
            repository,
            original.OwnerScopeId,
            "dev_B",
            Fingerprint('B'),
            "replacement",
            revoked,
            registeredAtUtc: Now.AddMinutes(2),
            retainedDevices: [],
            retainedChallenges: []);
        var restored = await repository.GetAsync(original.OwnerScopeId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(revokedResult, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(replacementResult, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(restored!.Devices.Select(device => device.DeviceId), Is.EqualTo(new[] { "dev_B" }));
            Assert.That(
                context.Records.AsNoTracking().Count(row =>
                    row.Partition == DeviceBindingPartition || row.Partition == KeyBindingPartition),
                Is.EqualTo(4));
        });
    }

    [Test]
    public async Task Issuing_a_challenge_does_not_require_device_bindings()
    {
        using var context = CreateContext();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        var ownerScope = OwnerScope('a');
        var challenge = Challenge("challenge_A", "dev_A");
        var issued = new DeviceRegistrationAggregate(ownerScope, 1, [challenge], []);
        var issuedResult = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                issued,
                ExpectedVersion: 0,
                [],
                [Audit("audit-challenge-issued", ownerScope, challenge.DeviceId)]),
            CancellationToken.None);

        Assert.That(issuedResult, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
    }

    [Test]
    public void Read_rejects_an_encrypted_aggregate_copied_to_another_owner_scope()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var storedAggregate = RegisteredAggregate(OwnerScope('a'), "dev_A", Fingerprint('A'), version: 1);
        var requestedOwnerScope = OwnerScope('b');
        SeedAggregate(context, encryptor, requestedOwnerScope, storedAggregate, rowVersion: 1);
        var repository = new EfDeviceRegistrationRepository(new HipRecordStore(context, encryptor));

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.GetAsync(
            requestedOwnerScope,
            CancellationToken.None));
    }

    [TestCase(1L, 2L)]
    [TestCase(2L, 1L)]
    public void Read_rejects_payload_and_database_version_mismatch(long payloadVersion, long rowVersion)
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var ownerScope = OwnerScope('a');
        var aggregate = RegisteredAggregate(ownerScope, "dev_A", Fingerprint('A'), payloadVersion);
        SeedAggregate(context, encryptor, ownerScope, aggregate, rowVersion);
        var repository = new EfDeviceRegistrationRepository(new HipRecordStore(context, encryptor));

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.GetAsync(
            ownerScope,
            CancellationToken.None));
    }

    [Test]
    public void Security_sensitive_read_rejects_a_legacy_plaintext_aggregate()
    {
        using var context = CreateContext();
        var ownerScope = OwnerScope('a');
        context.Records.Add(new HipDbRecord
        {
            Partition = AggregatePartition,
            Id = ownerScope,
            Json = "{}",
            AggregateVersion = 1,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now
        });
        context.SaveChanges();
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));

        Assert.ThrowsAsync<InvalidOperationException>(() => repository.GetAsync(
            ownerScope,
            CancellationToken.None));
    }

    [Test]
    public async Task Stale_owner_transition_returns_version_conflict_without_writing_its_audit()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var store = new HipRecordStore(context, encryptor);
        var repository = new EfDeviceRegistrationRepository(store);
        var (original, created) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "created");
        var revoked = original with
        {
            Version = original.Version + 1,
            Devices = [original.Devices.Single() with
            {
                RevocationState = DeviceRevocationState.Revoked,
                RevokedAtUtc = Now.AddMinutes(1)
            }]
        };
        var winner = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                revoked,
                original.Version,
                [],
                [Audit("audit-winner", original.OwnerScopeId, "dev_A")]),
            CancellationToken.None);
        var stale = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                revoked,
                original.Version,
                [],
                [Audit("audit-stale", original.OwnerScopeId, "dev_A")]),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(winner, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(stale, Is.EqualTo(DeviceRegistrationSaveOutcome.VersionConflict));
            Assert.That(
                context.Records.AsNoTracking().Any(row =>
                    row.Partition == AuditPartition && row.Id == "audit-stale"),
                Is.False);
        });
    }

    [Test]
    public async Task Stale_legacy_owner_guard_rejects_a_current_partition_transition()
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = new EfDeviceRegistrationRepository(new HipRecordStore(context, encryptor));
        var currentOwnerScope = OwnerScope('a');
        var legacyOwnerScope = OwnerScope('b');
        var firstLegacyDevice = RegisteredAggregate(
            legacyOwnerScope,
            "dev_legacy_a",
            Fingerprint('A'),
            version: 0).Devices.Single();
        var firstLegacyVersion = await IssueChallengeAsync(
            repository,
            legacyOwnerScope,
            current: null,
            firstLegacyDevice,
            "legacy-first");
        var secondLegacyDevice = RegisteredAggregate(
            legacyOwnerScope,
            "dev_legacy_b",
            Fingerprint('B'),
            version: 0).Devices.Single();
        _ = await IssueChallengeAsync(
            repository,
            legacyOwnerScope,
            firstLegacyVersion,
            secondLegacyDevice,
            "legacy-second");

        var currentChallenge = Challenge("challenge-current", "dev_current");
        var currentTransition = new DeviceRegistrationTransitionBatch(
            new DeviceRegistrationAggregate(currentOwnerScope, 1, [currentChallenge], []),
            ExpectedVersion: 0,
            NewBindings: [],
            AuditEntries: [Audit("audit-current-issued", currentOwnerScope, currentChallenge.DeviceId)],
            OwnerVersionGuards:
            [
                new DeviceRegistrationOwnerVersionGuard(currentOwnerScope, ExpectedVersion: 0),
                new DeviceRegistrationOwnerVersionGuard(legacyOwnerScope, firstLegacyVersion.Version)
            ]);

        var outcome = await repository.TrySaveAsync(currentTransition, CancellationToken.None);
        var currentAggregate = await repository.GetAsync(currentOwnerScope, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(outcome, Is.EqualTo(DeviceRegistrationSaveOutcome.VersionConflict));
            Assert.That(currentAggregate, Is.Null);
            Assert.That(
                context.Records.AsNoTracking().Any(row =>
                    row.Partition == AuditPartition && row.Id == "audit-current-issued"),
                Is.False);
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task Global_key_and_device_bindings_are_immutable_and_rollback_the_losing_owner(bool collideOnKey)
    {
        using var context = CreateContext();
        var encryptor = new DevelopmentHipRecordEncryptor();
        var repository = new EfDeviceRegistrationRepository(new HipRecordStore(context, encryptor));
        var (first, firstResult) = await RegisterDeviceAsync(
            repository,
            OwnerScope('a'),
            "dev_A",
            Fingerprint('A'),
            "first");
        var secondDevice = RegisteredAggregate(
            OwnerScope('b'),
            collideOnKey ? "dev_B" : "dev_A",
            collideOnKey ? Fingerprint('A') : Fingerprint('B'),
            version: 0).Devices.Single();
        var secondChallenged = await IssueChallengeAsync(
            repository,
            OwnerScope('b'),
            current: null,
            secondDevice,
            "second");
        var second = CompleteRegistration(secondChallenged, secondDevice);
        var secondResult = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                second,
                secondChallenged.Version,
                Bindings(second.Devices.Single(), second.OwnerScopeId),
                [Audit("audit-second-completed", second.OwnerScopeId, second.Devices.Single().DeviceId)]),
            CancellationToken.None);
        var losingAggregate = await repository.GetAsync(second.OwnerScopeId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstResult, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
            Assert.That(secondResult, Is.EqualTo(DeviceRegistrationSaveOutcome.BindingConflict));
            Assert.That(losingAggregate, Is.Not.Null);
            Assert.That(losingAggregate!.Devices, Is.Empty);
            Assert.That(losingAggregate.Challenges.Single().State, Is.EqualTo(DeviceRegistrationChallengeState.Pending));
            Assert.That(
                context.Records.AsNoTracking().Any(row =>
                    row.Partition == AuditPartition && row.Id == "audit-second-completed"),
                Is.False);
        });
    }

    [Test]
    public void Infrastructure_registration_selects_the_scoped_device_repository()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip_tests;Username=hip",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipInfrastructure:DatabaseProvider"] = "PostgreSQL"
            })
            .Build();

        services.AddHipInfrastructure(configuration);
        var descriptor = services.Last(service =>
            service.ServiceType == typeof(IDeviceRegistrationRepository));

        Assert.Multiple(() =>
        {
            Assert.That(descriptor.ImplementationType, Is.EqualTo(typeof(EfDeviceRegistrationRepository)));
            Assert.That(descriptor.Lifetime, Is.EqualTo(ServiceLifetime.Scoped));
        });
    }

    private static DeviceRegistrationAggregate RegisteredAggregate(
        string ownerScope,
        string deviceId,
        string fingerprint,
        long version)
    {
        var device = new RegisteredDevice(
            deviceId,
            "Test browser",
            DevicePlatformType.BrowserExtension,
            "1.0.0",
            "ECDSA-P256-SHA256",
            "public-key",
            fingerprint,
            DeviceTrustState.ProofOfPossessionVerified,
            DeviceRevocationState.Active,
            Now,
            Now,
            RevokedAtUtc: null);
        return new DeviceRegistrationAggregate(ownerScope, version, [], [device]);
    }

    private static async Task<(DeviceRegistrationAggregate Aggregate, DeviceRegistrationSaveOutcome Outcome)>
        RegisterDeviceAsync(
            EfDeviceRegistrationRepository repository,
            string ownerScope,
            string deviceId,
            string fingerprint,
            string auditPrefix,
            DeviceRegistrationAggregate? current = null,
            DateTimeOffset? registeredAtUtc = null,
            IReadOnlyCollection<RegisteredDevice>? retainedDevices = null,
            IReadOnlyCollection<DeviceRegistrationChallenge>? retainedChallenges = null)
    {
        var registrationTime = registeredAtUtc ?? Now;
        var device = RegisteredAggregate(ownerScope, deviceId, fingerprint, version: 0)
            .Devices.Single() with
        {
            RegisteredAtUtc = registrationTime,
            LastSeenAtUtc = registrationTime
        };
        var challenged = await IssueChallengeAsync(
            repository,
            ownerScope,
            current,
            device,
            auditPrefix,
            retainedChallenges);
        var completed = CompleteRegistration(challenged, device, retainedDevices);
        var outcome = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                completed,
                challenged.Version,
                Bindings(device, ownerScope),
                [Audit($"audit-{auditPrefix}-completed", ownerScope, deviceId)]),
            CancellationToken.None);
        return (completed, outcome);
    }

    private static async Task<DeviceRegistrationAggregate> IssueChallengeAsync(
        EfDeviceRegistrationRepository repository,
        string ownerScope,
        DeviceRegistrationAggregate? current,
        RegisteredDevice device,
        string auditPrefix,
        IReadOnlyCollection<DeviceRegistrationChallenge>? retainedChallenges = null)
    {
        current ??= new DeviceRegistrationAggregate(ownerScope, 0, [], []);
        var challenge = new DeviceRegistrationChallenge(
            $"challenge-{auditPrefix}",
            device.DeviceId,
            device.FriendlyName,
            device.PlatformType,
            device.ClientVersion,
            device.KeyAlgorithm,
            device.PublicKey,
            device.PublicKeyFingerprint,
            $"sha256:{new string('a', 64)}",
            device.RegisteredAtUtc.AddMinutes(-1),
            device.RegisteredAtUtc.AddMinutes(4),
            DeviceRegistrationChallengeState.Pending,
            ConsumedAtUtc: null);
        var challenged = current with
        {
            Version = current.Version + 1,
            Challenges = (retainedChallenges ?? current.Challenges).Append(challenge).ToArray()
        };
        var outcome = await repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                challenged,
                current.Version,
                [],
                [Audit($"audit-{auditPrefix}-issued", challenged.OwnerScopeId, device.DeviceId)]),
            CancellationToken.None);
        Assert.That(outcome, Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        return challenged;
    }

    private static DeviceRegistrationAggregate CompleteRegistration(
        DeviceRegistrationAggregate challenged,
        RegisteredDevice device,
        IReadOnlyCollection<RegisteredDevice>? retainedDevices = null)
    {
        var challenge = challenged.Challenges.Single(item =>
            string.Equals(item.DeviceId, device.DeviceId, StringComparison.Ordinal) &&
            item.State == DeviceRegistrationChallengeState.Pending);
        return challenged with
        {
            Version = challenged.Version + 1,
            Challenges = challenged.Challenges
                .Select(item => string.Equals(item.ChallengeId, challenge.ChallengeId, StringComparison.Ordinal)
                    ? item with
                    {
                        State = DeviceRegistrationChallengeState.Consumed,
                        ConsumedAtUtc = device.RegisteredAtUtc
                    }
                    : item)
                .ToArray(),
            Devices = (retainedDevices ?? challenged.Devices).Append(device).ToArray()
        };
    }

    private static DeviceRegistrationBinding[] Bindings(RegisteredDevice device, string ownerScope) =>
    [
        new("device-public-key", device.PublicKeyFingerprint, ownerScope, device.DeviceId),
        new("device-id", device.DeviceId, ownerScope, device.DeviceId)
    ];

    private static DeviceRegistrationChallenge Challenge(string challengeId, string deviceId) =>
        new(
            challengeId,
            deviceId,
            "Test browser",
            DevicePlatformType.BrowserExtension,
            "1.0.0",
            "ECDSA-P256-SHA256",
            "public-key",
            Fingerprint('A'),
            $"sha256:{new string('a', 64)}",
            Now,
            Now.AddMinutes(5),
            DeviceRegistrationChallengeState.Pending,
            ConsumedAtUtc: null);

    private static AuditLogEntry Audit(string id, string ownerScope, string deviceId) =>
        new(
            id,
            ownerScope,
            "ConsumerDevice.Registered",
            TargetType.DeviceKey,
            deviceId,
            "Privacy-safe device lifecycle transition.",
            Now,
            new Dictionary<string, string>(),
            AuditSeverity.Medium)
        {
            ActorRole = "Consumer"
        };

    private static string OwnerScope(char value) =>
        $"owner-hmac-sha256-v1:{new string(value, 64)}";

    private static string Fingerprint(char value) =>
        $"sha256:{new string(value, 43)}";

    private static void SeedAggregate(
        HipDbContext context,
        DevelopmentHipRecordEncryptor encryptor,
        string rowId,
        DeviceRegistrationAggregate aggregate,
        long rowVersion)
    {
        context.Records.Add(new HipDbRecord
        {
            Partition = AggregatePartition,
            Id = rowId,
            Json = encryptor.Protect(JsonSerializer.Serialize(aggregate, SerializerOptions())),
            AggregateVersion = rowVersion,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now
        });
        context.SaveChanges();
    }

    private static HipDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-device-registration-{Guid.NewGuid():N}")
            .Options;
        return new HipDbContext(options);
    }

    private static JsonSerializerOptions SerializerOptions() =>
        new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };
}
