using System.Security.Cryptography;
using HIP.Application.Devices;
using HIP.Application.Protocol;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Devices;

namespace HIP.Tests.Devices;

/// <summary>
/// Verifies consumer device ownership remains reachable and bounded during planned privacy-key rotation.
/// </summary>
public sealed class DeviceRegistrationPrivacyKeyRotationTests
{
    private const string CurrentKey = "device-registration-current-privacy-key";
    private const string LegacyKey = "device-registration-legacy-privacy-key";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Rotated_service_completes_lists_and_revokes_in_the_original_legacy_partition()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var legacyDerivation = Derivation(LegacyKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock);
        var rotatedService = Service(repository, rotatedDerivation, clock);
        var issued = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key),
            CancellationToken.None);

        var completed = await Complete(rotatedService, "consumer-A", issued.Challenge!, key);
        var listed = await rotatedService.ListAsync("consumer-A", CancellationToken.None);
        var revoked = await rotatedService.RevokeAsync(
            "consumer-A",
            completed.Device!.DeviceId,
            CancellationToken.None);
        var legacyAggregate = await repository.GetAsync(
            legacyDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);
        var currentAggregate = await repository.GetAsync(
            rotatedDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(completed.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(listed.Select(device => device.DeviceId), Does.Contain(completed.Device.DeviceId));
            Assert.That(revoked.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(legacyAggregate!.Devices.Single().RevocationState, Is.EqualTo(DeviceRevocationState.Revoked));
            Assert.That(currentAggregate, Is.Null);
        });
    }

    [Test]
    public async Task New_challenges_use_only_the_current_partition_after_rotation()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var legacyDerivation = Derivation(LegacyKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock);
        var rotatedService = Service(repository, rotatedDerivation, clock);
        var oldChallenge = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(oldKey, "Old browser"),
            CancellationToken.None);
        var oldDevice = await Complete(legacyService, "consumer-A", oldChallenge.Challenge!, oldKey);
        _ = await legacyService.RevokeAsync("consumer-A", oldDevice.Device!.DeviceId, CancellationToken.None);
        var legacyBefore = await repository.GetAsync(
            legacyDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        var issued = await rotatedService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(newKey, "New browser"),
            CancellationToken.None);
        var legacyAfter = await repository.GetAsync(
            legacyDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);
        var current = await repository.GetAsync(
            rotatedDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(current!.Challenges.Single().ChallengeId, Is.EqualTo(issued.Challenge!.ChallengeId));
            Assert.That(legacyAfter, Is.EqualTo(legacyBefore));
        });
    }

    [Test]
    public async Task Legacy_active_devices_count_toward_the_rotated_device_limit()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var policy = DeviceRegistrationPolicy.Default with
        {
            MaximumDevices = 1,
            MaximumRetainedDevices = 1
        };
        var legacyDerivation = Derivation(LegacyKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock, policy);
        var rotatedService = Service(repository, rotatedDerivation, clock, policy);
        var oldChallenge = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(oldKey, "Old browser"),
            CancellationToken.None);
        _ = await Complete(legacyService, "consumer-A", oldChallenge.Challenge!, oldKey);

        var result = await rotatedService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(newKey, "Limit bypass attempt"),
            CancellationToken.None);
        var current = await repository.GetAsync(
            rotatedDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Conflict));
            Assert.That(current, Is.Null);
        });
    }

    [Test]
    public async Task Legacy_pending_challenges_count_toward_the_rotated_pending_limit()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var policy = DeviceRegistrationPolicy.Default with { MaximumPendingChallenges = 1 };
        var legacyDerivation = Derivation(LegacyKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock, policy);
        var rotatedService = Service(repository, rotatedDerivation, clock, policy);
        _ = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(oldKey, "Old pending browser"),
            CancellationToken.None);

        var result = await rotatedService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(newKey, "Pending limit bypass attempt"),
            CancellationToken.None);

        Assert.That(result.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Conflict));
    }

    [Test]
    public async Task Completing_a_legacy_challenge_cannot_bypass_current_partition_capacity()
    {
        using var oldKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var legacyDerivation = Derivation(LegacyKey);
        var currentDerivation = Derivation(CurrentKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock);
        var currentService = Service(repository, currentDerivation, clock);
        var restrictivePolicy = DeviceRegistrationPolicy.Default with
        {
            MaximumDevices = 1,
            MaximumRetainedDevices = 1
        };
        var rotatedService = Service(repository, rotatedDerivation, clock, restrictivePolicy);
        var oldChallenge = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(oldKey, "Old pending browser"),
            CancellationToken.None);
        var currentChallenge = await currentService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(currentKey, "Current browser"),
            CancellationToken.None);
        _ = await Complete(currentService, "consumer-A", currentChallenge.Challenge!, currentKey);

        var result = await Complete(rotatedService, "consumer-A", oldChallenge.Challenge!, oldKey);

        Assert.That(result.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Conflict));
    }

    [Test]
    public async Task Concurrent_current_and_legacy_completions_share_one_atomic_device_limit()
    {
        using var legacyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var legacyDerivation = Derivation(LegacyKey);
        var currentDerivation = Derivation(CurrentKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock);
        var currentService = Service(repository, currentDerivation, clock);
        var legacyChallenge = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(legacyKey, "Legacy browser"),
            CancellationToken.None);
        var currentChallenge = await currentService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(currentKey, "Current browser"),
            CancellationToken.None);
        var coordinatedRepository = new CoordinatedSaveRepository(repository);
        var rotatedService = Service(
            coordinatedRepository,
            rotatedDerivation,
            clock,
            DeviceRegistrationPolicy.Default with
            {
                MaximumDevices = 1,
                MaximumRetainedDevices = 1
            });

        var results = await Task.WhenAll(
            Complete(rotatedService, "consumer-A", legacyChallenge.Challenge!, legacyKey),
            Complete(rotatedService, "consumer-A", currentChallenge.Challenge!, currentKey));
        var aggregates = await Task.WhenAll(rotatedDerivation.OwnerScopeIds("consumer-A")
            .Select(scope => repository.GetAsync(scope, CancellationToken.None)));

        Assert.Multiple(() =>
        {
            Assert.That(results.Select(result => result.Outcome), Is.EquivalentTo(new[]
            {
                DeviceRegistrationOutcome.Succeeded,
                DeviceRegistrationOutcome.Conflict
            }));
            Assert.That(aggregates.Sum(aggregate => aggregate?.Devices.Count(device =>
                device.RevocationState == DeviceRevocationState.Active) ?? 0), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Legacy_completion_between_issue_read_and_save_invalidates_the_current_partition_write()
    {
        using var legacyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var repository = new InMemoryDeviceRegistrationRepository();
        var clock = new MutableTimeProvider(Now);
        var legacyDerivation = Derivation(LegacyKey);
        var rotatedDerivation = Derivation(CurrentKey, [LegacyKey]);
        var legacyService = Service(repository, legacyDerivation, clock);
        var legacyChallenge = await legacyService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(legacyKey, "Legacy browser"),
            CancellationToken.None);
        DeviceRegistrationCompletionResult? completed = null;
        var injectingRepository = new BeforeFirstSaveRepository(
            repository,
            async () =>
            {
                completed = await Complete(
                    legacyService,
                    "consumer-A",
                    legacyChallenge.Challenge!,
                    legacyKey);
            });
        var rotatedService = Service(
            injectingRepository,
            rotatedDerivation,
            clock,
            DeviceRegistrationPolicy.Default with
            {
                MaximumDevices = 1,
                MaximumRetainedDevices = 1
            });

        var issued = await rotatedService.IssueChallengeAsync(
            "consumer-A",
            StartRequest(currentKey, "Current browser"),
            CancellationToken.None);
        var currentAggregate = await repository.GetAsync(
            rotatedDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(completed!.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(issued.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Conflict));
            Assert.That(currentAggregate, Is.Null);
        });
    }

    [Test]
    public async Task Listing_deduplicates_exact_records_but_fails_closed_on_ambiguous_duplicates()
    {
        var derivation = Derivation(CurrentKey, [LegacyKey]);
        var scopes = derivation.OwnerScopeIds("consumer-A");
        var device = RegisteredDevice("dev-shared", "Browser");
        var exactRepository = new StaticDeviceRegistrationRepository(new Dictionary<string, DeviceRegistrationAggregate>
        {
            [scopes[0]] = new(scopes[0], 1, [], [device]),
            [scopes[1]] = new(scopes[1], 1, [], [device])
        });
        var ambiguousRepository = new StaticDeviceRegistrationRepository(new Dictionary<string, DeviceRegistrationAggregate>
        {
            [scopes[0]] = new(scopes[0], 1, [], [device]),
            [scopes[1]] = new(scopes[1], 1, [], [device with { FriendlyName = "Different browser" }])
        });
        var clock = new MutableTimeProvider(Now);
        var exactService = Service(exactRepository, derivation, clock);
        var ambiguousService = Service(ambiguousRepository, derivation, clock);
        var exact = await exactService.ListAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(exact, Has.Count.EqualTo(1));
            Assert.That(
                async () => await ambiguousService.ListAsync("consumer-A", CancellationToken.None),
                Throws.InstanceOf<InvalidOperationException>());
        });
    }

    private static DeviceRegistrationKeyDerivation Derivation(
        string currentKey,
        IReadOnlyCollection<string>? legacyKeys = null) =>
        new(new PrivacyHashingOptions(
            currentKey,
            AllowDevelopmentKey: false,
            LegacyKeys: legacyKeys));

    private static DeviceRegistrationService Service(
        IDeviceRegistrationRepository repository,
        DeviceRegistrationKeyDerivation keyDerivation,
        TimeProvider clock,
        DeviceRegistrationPolicy? policy = null) =>
        new(
            repository,
            new Es256DeviceProofVerifier(),
            new Rfc8785CanonicalJsonService(),
            keyDerivation,
            new AuditLogService(new InMemoryAuditLogRepository()),
            clock,
            policy ?? DeviceRegistrationPolicy.Default);

    private static async Task<DeviceRegistrationCompletionResult> Complete(
        IDeviceRegistrationService service,
        string ownerId,
        DeviceRegistrationChallengeResponse challenge,
        ECDsa key) =>
        await service.CompleteAsync(
            ownerId,
            challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(
                challenge.SigningInput,
                Sign(key, Decode(challenge.SigningInput))),
            CancellationToken.None);

    private static StartDeviceRegistrationRequest StartRequest(
        ECDsa key,
        string friendlyName = "Test browser") =>
        new(
            friendlyName,
            DevicePlatformType.BrowserExtension,
            "1.0.0",
            Es256DeviceProofVerifier.Algorithm,
            Encode(key.ExportSubjectPublicKeyInfo()));

    private static RegisteredDevice RegisteredDevice(string deviceId, string friendlyName) =>
        new(
            deviceId,
            friendlyName,
            DevicePlatformType.BrowserExtension,
            "1.0.0",
            Es256DeviceProofVerifier.Algorithm,
            "public-key",
            $"fingerprint-{deviceId}",
            DeviceTrustState.ProofOfPossessionVerified,
            DeviceRevocationState.Active,
            Now,
            Now,
            RevokedAtUtc: null);

    private static string Sign(ECDsa key, ReadOnlySpan<byte> signingInput) =>
        Encode(key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    private static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Decode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '='));
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class StaticDeviceRegistrationRepository(
        IReadOnlyDictionary<string, DeviceRegistrationAggregate> aggregates) : IDeviceRegistrationRepository
    {
        public Task<DeviceRegistrationAggregate?> GetAsync(
            string ownerScopeId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            aggregates.TryGetValue(ownerScopeId, out var aggregate);
            return Task.FromResult(aggregate);
        }

        public Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
            DeviceRegistrationTransitionBatch transition,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class CoordinatedSaveRepository(IDeviceRegistrationRepository inner)
        : IDeviceRegistrationRepository
    {
        private readonly TaskCompletionSource bothSavesEntered = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int saveCalls;

        public Task<DeviceRegistrationAggregate?> GetAsync(
            string ownerScopeId,
            CancellationToken cancellationToken) =>
            inner.GetAsync(ownerScopeId, cancellationToken);

        public async Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
            DeviceRegistrationTransitionBatch transition,
            CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref saveCalls);
            if (call <= 2)
            {
                if (call == 2)
                {
                    bothSavesEntered.TrySetResult();
                }

                await bothSavesEntered.Task.WaitAsync(cancellationToken);
            }

            return await inner.TrySaveAsync(transition, cancellationToken);
        }
    }

    private sealed class BeforeFirstSaveRepository(
        IDeviceRegistrationRepository inner,
        Func<Task> beforeFirstSave) : IDeviceRegistrationRepository
    {
        private int saveCalls;

        public Task<DeviceRegistrationAggregate?> GetAsync(
            string ownerScopeId,
            CancellationToken cancellationToken) =>
            inner.GetAsync(ownerScopeId, cancellationToken);

        public async Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
            DeviceRegistrationTransitionBatch transition,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref saveCalls) == 1)
            {
                await beforeFirstSave();
            }

            return await inner.TrySaveAsync(transition, cancellationToken);
        }
    }
}
