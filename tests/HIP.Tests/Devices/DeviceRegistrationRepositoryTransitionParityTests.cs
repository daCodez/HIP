using HIP.Application.Devices;
using HIP.Domain.Audit;
using HIP.Domain.Devices;
using HIP.Domain.Review;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Devices;

/// <summary>Ensures development and production repositories enforce identical lifecycle invariants.</summary>
public sealed class DeviceRegistrationRepositoryTransitionParityTests
{
    private const string EfRepository = "ef";
    private const string InMemoryRepository = "in-memory";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 18, 0, 0, TimeSpan.Zero);

    [TestCase(EfRepository, "public-key")]
    [TestCase(EfRepository, "signing-digest")]
    [TestCase(EfRepository, "expiry")]
    [TestCase(InMemoryRepository, "public-key")]
    [TestCase(InMemoryRepository, "signing-digest")]
    [TestCase(InMemoryRepository, "expiry")]
    public async Task Existing_challenge_proof_material_is_immutable(
        string repositoryKind,
        string mutation)
    {
        using var harness = CreateRepository(repositoryKind);
        var challenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [challenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-challenge-issued"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var changedChallenge = mutation switch
        {
            "public-key" => challenge with { PublicKey = "different-public-key" },
            "signing-digest" => challenge with { SigningInputDigest = Digest('b') },
            "expiry" => challenge with { ExpiresAtUtc = challenge.ExpiresAtUtc.AddMinutes(1) },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
        var changed = issued with { Version = 2, Challenges = [changedChallenge] };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            changed,
            1,
            [],
            $"audit-challenge-{mutation}"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Consumed_challenge_cannot_be_resurrected(string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var challenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [challenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-issued-for-resurrection"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var device = DeviceForChallenge(challenge, Now.AddMinutes(1));
        var consumed = issued with
        {
            Version = 2,
            Challenges = [challenge with
            {
                State = DeviceRegistrationChallengeState.Consumed,
                ConsumedAtUtc = Now.AddMinutes(1)
            }],
            Devices = [device]
        };
        Assert.That(
            await SaveAsync(
                harness.Repository,
                consumed,
                1,
                Bindings(device),
                "audit-consumed-for-resurrection"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var resurrected = consumed with
        {
            Version = 3,
            Challenges = [challenge]
        };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            resurrected,
            2,
            [],
            "audit-resurrected"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Challenge_cannot_be_consumed_at_or_after_expiry(string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var challenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [challenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-issued-for-late-consume"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var consumedTooLate = issued with
        {
            Version = 2,
            Challenges = [challenge with
            {
                State = DeviceRegistrationChallengeState.Consumed,
                ConsumedAtUtc = challenge.ExpiresAtUtc
            }]
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => SaveAsync(
            harness.Repository,
            consumedTooLate,
            1,
            [],
            "audit-late-consume"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Consumed_challenge_timestamp_is_immutable(string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var challenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [challenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-issued-for-consumed-time"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var consumedChallenge = challenge with
        {
            State = DeviceRegistrationChallengeState.Consumed,
            ConsumedAtUtc = Now.AddMinutes(1)
        };
        var device = DeviceForChallenge(challenge, consumedChallenge.ConsumedAtUtc!.Value);
        var consumed = issued with
        {
            Version = 2,
            Challenges = [consumedChallenge],
            Devices = [device]
        };
        Assert.That(
            await SaveAsync(
                harness.Repository,
                consumed,
                1,
                Bindings(device),
                "audit-first-consumed-time"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var timestampChanged = consumed with
        {
            Version = 3,
            Challenges = [consumedChallenge with { ConsumedAtUtc = Now.AddMinutes(2) }]
        };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            timestampChanged,
            2,
            [],
            "audit-changed-consumed-time"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Consumed_challenge_can_be_pruned_only_while_a_new_challenge_is_issued(
        string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var originalChallenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [originalChallenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-issued-for-prune"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var device = DeviceForChallenge(originalChallenge, Now.AddMinutes(1));
        var consumed = issued with
        {
            Version = 2,
            Challenges = [originalChallenge with
            {
                State = DeviceRegistrationChallengeState.Consumed,
                ConsumedAtUtc = Now.AddMinutes(1)
            }],
            Devices = [device]
        };
        Assert.That(
            await SaveAsync(
                harness.Repository,
                consumed,
                1,
                Bindings(device),
                "audit-consumed-for-prune"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var prunedWithoutReplacement = consumed with { Version = 3, Challenges = [] };
        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            prunedWithoutReplacement,
            2,
            [],
            "audit-invalid-prune"));
        var replacementChallenge = Challenge("challenge_B", "dev_B", Now.AddMinutes(2));
        var prunedDuringIssue = consumed with
        {
            Version = 3,
            Challenges = [replacementChallenge]
        };

        Assert.That(
            await SaveAsync(harness.Repository, prunedDuringIssue, 2, [], "audit-valid-prune"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Pending_challenge_can_be_pruned_only_after_it_expires(string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var originalChallenge = Challenge("challenge_A", "dev_A", Now);
        var issued = new DeviceRegistrationAggregate(OwnerScope, 1, [originalChallenge], []);
        Assert.That(
            await SaveAsync(harness.Repository, issued, 0, [], "audit-issued-for-expiry-prune"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var tooEarly = issued with
        {
            Version = 2,
            Challenges = [Challenge("challenge_B", "dev_B", Now.AddMinutes(4))]
        };
        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            tooEarly,
            1,
            [],
            "audit-too-early-prune"));
        var afterExpiry = issued with
        {
            Version = 2,
            Challenges = [Challenge("challenge_B", "dev_B", originalChallenge.ExpiresAtUtc)]
        };

        Assert.That(
            await SaveAsync(harness.Repository, afterExpiry, 1, [], "audit-after-expiry-prune"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
    }

    [TestCase(EfRepository, 0)]
    [TestCase(EfRepository, 1)]
    [TestCase(InMemoryRepository, 0)]
    [TestCase(InMemoryRepository, 1)]
    public async Task Newly_added_device_requires_both_immutable_bindings(
        string repositoryKind,
        int bindingCount)
    {
        using var harness = CreateRepository(repositoryKind);
        var device = Device("dev_A", Fingerprint('A'));
        var challenged = await IssueChallengeAsync(
            harness.Repository,
            current: null,
            device,
            "incomplete-bindings");
        var aggregate = CompleteRegistration(challenged, device);

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            aggregate,
            challenged.Version,
            Bindings(device).Take(bindingCount).ToArray(),
            $"audit-incomplete-bindings-{bindingCount}"));
    }

    [TestCase(EfRepository, "friendly-name")]
    [TestCase(EfRepository, "client-version")]
    [TestCase(EfRepository, "public-key")]
    [TestCase(EfRepository, "registered-at")]
    [TestCase(InMemoryRepository, "friendly-name")]
    [TestCase(InMemoryRepository, "client-version")]
    [TestCase(InMemoryRepository, "public-key")]
    [TestCase(InMemoryRepository, "registered-at")]
    public async Task Existing_device_identity_and_metadata_are_immutable(
        string repositoryKind,
        string mutation)
    {
        using var harness = CreateRepository(repositoryKind);
        var device = Device("dev_A", Fingerprint('A'));
        var original = await RegisterDeviceAsync(
            harness.Repository,
            current: null,
            device,
            "device-created");
        var changedDevice = mutation switch
        {
            "friendly-name" => device with { FriendlyName = "Silently renamed" },
            "client-version" => device with { ClientVersion = "9.9.9" },
            "public-key" => device with { PublicKey = "different-public-key" },
            "registered-at" => device with
            {
                RegisteredAtUtc = device.RegisteredAtUtc.AddMinutes(1),
                LastSeenAtUtc = device.LastSeenAtUtc.AddMinutes(1)
            },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
        var mutated = original with
        {
            Version = original.Version + 1,
            Devices = [changedDevice]
        };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            mutated,
            original.Version,
            [],
            $"audit-device-{mutation}"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Pruned_device_binding_cannot_be_reinserted(string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var firstDevice = Device("dev_A", Fingerprint('A'));
        var created = await RegisterDeviceAsync(
            harness.Repository,
            current: null,
            firstDevice,
            "first-created");
        var firstRevoked = firstDevice with
        {
            RevocationState = DeviceRevocationState.Revoked,
            RevokedAtUtc = Now.AddMinutes(1)
        };
        var revoked = created with
        {
            Version = created.Version + 1,
            Devices = [firstRevoked]
        };
        Assert.That(
            await SaveAsync(
                harness.Repository,
                revoked,
                created.Version,
                [],
                "audit-first-revoked"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var secondDevice = Device("dev_B", Fingerprint('B')) with
        {
            RegisteredAtUtc = Now.AddMinutes(2),
            LastSeenAtUtc = Now.AddMinutes(2)
        };
        var replaced = await RegisterDeviceAsync(
            harness.Repository,
            revoked,
            secondDevice,
            "second-created",
            retainedDevices: [],
            retainedChallenges: []);
        var secondRevoked = secondDevice with
        {
            RevocationState = DeviceRevocationState.Revoked,
            RevokedAtUtc = Now.AddMinutes(3)
        };
        var replacementRevoked = replaced with
        {
            Version = replaced.Version + 1,
            Devices = [secondRevoked]
        };
        Assert.That(
            await SaveAsync(
                harness.Repository,
                replacementRevoked,
                replaced.Version,
                [],
                "audit-second-revoked"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        var reusedDevice = firstDevice with
        {
            RegisteredAtUtc = Now.AddMinutes(4),
            LastSeenAtUtc = Now.AddMinutes(4)
        };
        var challengedForReuse = await IssueChallengeAsync(
            harness.Repository,
            replacementRevoked,
            reusedDevice,
            "first-reused");
        var attemptedReuse = CompleteRegistration(
            challengedForReuse,
            reusedDevice,
            retainedDevices: []);

        Assert.That(
            await SaveAsync(
                harness.Repository,
                attemptedReuse,
                challengedForReuse.Version,
                Bindings(reusedDevice),
                "audit-first-reused-completed"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.BindingConflict));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Added_device_requires_its_challenge_to_be_consumed_in_the_same_transition(
        string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var device = Device("dev_A", Fingerprint('A'));
        var challenged = await IssueChallengeAsync(
            harness.Repository,
            current: null,
            device,
            "pending-proof");
        var bypass = challenged with
        {
            Version = challenged.Version + 1,
            Devices = [device]
        };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            bypass,
            challenged.Version,
            Bindings(device),
            "audit-pending-proof-bypass"));
    }

    [TestCase(EfRepository)]
    [TestCase(InMemoryRepository)]
    public async Task Newly_consumed_challenge_requires_its_device_in_the_same_transition(
        string repositoryKind)
    {
        using var harness = CreateRepository(repositoryKind);
        var device = Device("dev_A", Fingerprint('A'));
        var challenged = await IssueChallengeAsync(
            harness.Repository,
            current: null,
            device,
            "missing-device");
        var consumedWithoutDevice = CompleteRegistration(challenged, device) with
        {
            Devices = []
        };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            consumedWithoutDevice,
            challenged.Version,
            [],
            "audit-consumed-without-device"));
    }

    [TestCase(EfRepository, "friendly-name")]
    [TestCase(EfRepository, "public-key")]
    [TestCase(EfRepository, "registered-at")]
    [TestCase(EfRepository, "last-seen")]
    [TestCase(InMemoryRepository, "friendly-name")]
    [TestCase(InMemoryRepository, "public-key")]
    [TestCase(InMemoryRepository, "registered-at")]
    [TestCase(InMemoryRepository, "last-seen")]
    public async Task Registered_device_must_match_the_consumed_challenge(
        string repositoryKind,
        string mutation)
    {
        using var harness = CreateRepository(repositoryKind);
        var device = Device("dev_A", Fingerprint('A'));
        var challenged = await IssueChallengeAsync(
            harness.Repository,
            current: null,
            device,
            "mismatched-device");
        var completed = CompleteRegistration(challenged, device);
        var mismatchedDevice = mutation switch
        {
            "friendly-name" => device with { FriendlyName = "Different browser" },
            "public-key" => device with { PublicKey = "different-public-key" },
            "registered-at" => device with
            {
                RegisteredAtUtc = device.RegisteredAtUtc.AddMinutes(1),
                LastSeenAtUtc = device.LastSeenAtUtc.AddMinutes(1)
            },
            "last-seen" => device with { LastSeenAtUtc = device.LastSeenAtUtc.AddMinutes(1) },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
        var mismatched = completed with { Devices = [mismatchedDevice] };

        Assert.ThrowsAsync<ArgumentException>(() => SaveAsync(
            harness.Repository,
            mismatched,
            challenged.Version,
            Bindings(mismatchedDevice),
            $"audit-mismatched-device-{mutation}"));
    }

    private static async Task<DeviceRegistrationAggregate> RegisterDeviceAsync(
        IDeviceRegistrationRepository repository,
        DeviceRegistrationAggregate? current,
        RegisteredDevice device,
        string auditPrefix,
        IReadOnlyCollection<RegisteredDevice>? retainedDevices = null,
        IReadOnlyCollection<DeviceRegistrationChallenge>? retainedChallenges = null)
    {
        var challenged = await IssueChallengeAsync(
            repository,
            current,
            device,
            auditPrefix,
            retainedChallenges);
        var completed = CompleteRegistration(challenged, device, retainedDevices);
        Assert.That(
            await SaveAsync(
                repository,
                completed,
                challenged.Version,
                Bindings(device),
                $"audit-{auditPrefix}-completed"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
        return completed;
    }

    private static async Task<DeviceRegistrationAggregate> IssueChallengeAsync(
        IDeviceRegistrationRepository repository,
        DeviceRegistrationAggregate? current,
        RegisteredDevice device,
        string auditPrefix,
        IReadOnlyCollection<DeviceRegistrationChallenge>? retainedChallenges = null)
    {
        current ??= new DeviceRegistrationAggregate(OwnerScope, 0, [], []);
        var challenge = ChallengeForDevice(
            $"challenge-{auditPrefix}",
            device,
            device.RegisteredAtUtc.AddMinutes(-1));
        var challenged = current with
        {
            Version = current.Version + 1,
            Challenges = (retainedChallenges ?? current.Challenges).Append(challenge).ToArray()
        };
        Assert.That(
            await SaveAsync(
                repository,
                challenged,
                current.Version,
                [],
                $"audit-{auditPrefix}-issued"),
            Is.EqualTo(DeviceRegistrationSaveOutcome.Succeeded));
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
        var consumed = challenge with
        {
            State = DeviceRegistrationChallengeState.Consumed,
            ConsumedAtUtc = device.RegisteredAtUtc
        };
        return challenged with
        {
            Version = challenged.Version + 1,
            Challenges = challenged.Challenges
                .Select(item => string.Equals(item.ChallengeId, challenge.ChallengeId, StringComparison.Ordinal)
                    ? consumed
                    : item)
                .ToArray(),
            Devices = (retainedDevices ?? challenged.Devices).Append(device).ToArray()
        };
    }

    private static Task<DeviceRegistrationSaveOutcome> SaveAsync(
        IDeviceRegistrationRepository repository,
        DeviceRegistrationAggregate aggregate,
        long expectedVersion,
        IReadOnlyCollection<DeviceRegistrationBinding> bindings,
        string auditId) =>
        repository.TrySaveAsync(
            new DeviceRegistrationTransitionBatch(
                aggregate,
                expectedVersion,
                bindings,
                [Audit(auditId, aggregate.OwnerScopeId)]),
            CancellationToken.None);

    private static RepositoryHarness CreateRepository(string repositoryKind)
    {
        if (repositoryKind == InMemoryRepository)
        {
            return new RepositoryHarness(new InMemoryDeviceRegistrationRepository(), null);
        }

        if (repositoryKind != EfRepository)
        {
            throw new ArgumentOutOfRangeException(nameof(repositoryKind));
        }

        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-device-transition-parity-{Guid.NewGuid():N}")
            .Options;
        var context = new HipDbContext(options);
        var repository = new EfDeviceRegistrationRepository(
            new HipRecordStore(context, new DevelopmentHipRecordEncryptor()));
        return new RepositoryHarness(repository, context);
    }

    private static DeviceRegistrationChallenge Challenge(
        string challengeId,
        string deviceId,
        DateTimeOffset issuedAtUtc) =>
        new(
            challengeId,
            deviceId,
            "Test browser",
            DevicePlatformType.BrowserExtension,
            "1.0.0",
            "ECDSA-P256-SHA256",
            "public-key",
            Fingerprint('A'),
            Digest('a'),
            issuedAtUtc,
            issuedAtUtc.AddMinutes(5),
            DeviceRegistrationChallengeState.Pending,
            ConsumedAtUtc: null);

    private static DeviceRegistrationChallenge ChallengeForDevice(
        string challengeId,
        RegisteredDevice device,
        DateTimeOffset issuedAtUtc) =>
        new(
            challengeId,
            device.DeviceId,
            device.FriendlyName,
            device.PlatformType,
            device.ClientVersion,
            device.KeyAlgorithm,
            device.PublicKey,
            device.PublicKeyFingerprint,
            Digest('a'),
            issuedAtUtc,
            issuedAtUtc.AddMinutes(5),
            DeviceRegistrationChallengeState.Pending,
            ConsumedAtUtc: null);

    private static RegisteredDevice Device(string deviceId, string fingerprint) =>
        new(
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

    private static RegisteredDevice DeviceForChallenge(
        DeviceRegistrationChallenge challenge,
        DateTimeOffset registeredAtUtc) =>
        new(
            challenge.DeviceId,
            challenge.FriendlyName,
            challenge.PlatformType,
            challenge.ClientVersion,
            challenge.KeyAlgorithm,
            challenge.PublicKey,
            challenge.PublicKeyFingerprint,
            DeviceTrustState.ProofOfPossessionVerified,
            DeviceRevocationState.Active,
            registeredAtUtc,
            registeredAtUtc,
            RevokedAtUtc: null);

    private static DeviceRegistrationBinding[] Bindings(RegisteredDevice device) =>
    [
        new("device-public-key", device.PublicKeyFingerprint, OwnerScope, device.DeviceId),
        new("device-id", device.DeviceId, OwnerScope, device.DeviceId)
    ];

    private static AuditLogEntry Audit(string id, string ownerScope) =>
        new(
            id,
            ownerScope,
            "ConsumerDevice.Registered",
            TargetType.DeviceKey,
            "device",
            "Privacy-safe device lifecycle transition.",
            Now,
            new Dictionary<string, string>(),
            AuditSeverity.Medium)
        {
            ActorRole = "Consumer"
        };

    private static string Digest(char value) => $"sha256:{new string(value, 64)}";

    private static string Fingerprint(char value) => $"sha256:{new string(value, 43)}";

    private static string OwnerScope => $"owner-hmac-sha256-v1:{new string('a', 64)}";

    private sealed class RepositoryHarness(
        IDeviceRegistrationRepository repository,
        IDisposable? lifetime) : IDisposable
    {
        public IDeviceRegistrationRepository Repository { get; } = repository;

        public void Dispose() => lifetime?.Dispose();
    }
}
