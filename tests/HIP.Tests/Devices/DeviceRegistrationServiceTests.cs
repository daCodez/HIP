using System.Security.Cryptography;
using HIP.Application.Devices;
using HIP.Application.Protocol;
using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Devices;

namespace HIP.Tests.Devices;

[TestFixture]
public sealed class DeviceRegistrationServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 20, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Challenge_stores_only_an_exact_digest_and_valid_proof_registers_the_device()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();

        var issued = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key, "Work laptop"),
            CancellationToken.None);
        var signingInput = Decode(issued.Challenge!.SigningInput);
        var signature = Sign(key, signingInput);
        var stored = await fixture.Repository.GetAsync(
            fixture.KeyDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        var completed = await fixture.Service.CompleteAsync(
            "consumer-A",
            issued.Challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(issued.Challenge.SigningInput, signature),
            CancellationToken.None);
        var devices = await fixture.Service.ListAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(issued.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(stored!.Challenges.Single().SigningInputDigest, Does.StartWith("sha256:"));
            Assert.That(stored.Challenges.Single().SigningInputDigest, Is.Not.EqualTo(issued.Challenge.SigningInput));
            Assert.That(completed.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(devices, Has.Count.EqualTo(1));
            Assert.That(devices.Single().DeviceId, Is.EqualTo(issued.Challenge.DeviceId));
            Assert.That(devices.Single().FriendlyName, Is.EqualTo("Work laptop"));
            Assert.That(devices.Single().TrustState, Is.EqualTo(DeviceTrustState.ProofOfPossessionVerified));
            Assert.That(fixture.Repository.AuditEntries, Is.Not.Empty);
            Assert.That(fixture.Repository.AuditEntries.All(AuditLogIntegrity.Verify), Is.True);
            Assert.That(devices.Single().RevocationState, Is.EqualTo(DeviceRevocationState.Active));
        });
    }

    [Test]
    public async Task Challenge_and_device_ownership_are_exact_and_non_disclosing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var issued = await fixture.Service.IssueChallengeAsync(
            "Consumer-Case-Sensitive",
            StartRequest(key),
            CancellationToken.None);
        var completion = new CompleteDeviceRegistrationRequest(
            issued.Challenge!.SigningInput,
            Sign(key, Decode(issued.Challenge.SigningInput)));

        var wrongOwner = await fixture.Service.CompleteAsync(
            "consumer-case-sensitive",
            issued.Challenge.ChallengeId,
            completion,
            CancellationToken.None);
        var owner = await fixture.Service.CompleteAsync(
            "Consumer-Case-Sensitive",
            issued.Challenge.ChallengeId,
            completion,
            CancellationToken.None);
        var wrongList = await fixture.Service.ListAsync("consumer-case-sensitive", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(wrongOwner.Outcome, Is.EqualTo(DeviceRegistrationOutcome.NotFound));
            Assert.That(wrongOwner.Message, Is.EqualTo(DeviceRegistrationMessages.ResourceUnavailable));
            Assert.That(owner.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(wrongList, Is.Empty);
        });
    }

    [Test]
    public async Task Expired_challenge_fails_at_the_exact_server_owned_boundary()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var issued = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key),
            CancellationToken.None);
        fixture.Clock.UtcNow = issued.Challenge!.ExpiresAtUtc;

        var completed = await fixture.Service.CompleteAsync(
            "consumer-A",
            issued.Challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(
                issued.Challenge.SigningInput,
                Sign(key, Decode(issued.Challenge.SigningInput))),
            CancellationToken.None);
        var devices = await fixture.Service.ListAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(completed.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Expired));
            Assert.That(devices, Is.Empty);
        });
    }

    [Test]
    public async Task Tampered_signing_input_and_signature_fail_without_consuming_the_challenge()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var issued = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key),
            CancellationToken.None);
        var signingInput = Decode(issued.Challenge!.SigningInput);
        var signature = Sign(key, signingInput);
        var invalidSignature = (signature[0] == 'A' ? 'B' : 'A') + signature[1..];
        var tamperedInput = signingInput.ToArray();
        tamperedInput[^1] ^= 1;

        var tamperedPayload = await fixture.Service.CompleteAsync(
            "consumer-A",
            issued.Challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(Encode(tamperedInput), signature),
            CancellationToken.None);
        var tamperedSignature = await fixture.Service.CompleteAsync(
            "consumer-A",
            issued.Challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(issued.Challenge.SigningInput, invalidSignature),
            CancellationToken.None);
        var valid = await fixture.Service.CompleteAsync(
            "consumer-A",
            issued.Challenge.ChallengeId,
            new CompleteDeviceRegistrationRequest(issued.Challenge.SigningInput, signature),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(tamperedPayload.Outcome, Is.EqualTo(DeviceRegistrationOutcome.InvalidProof));
            Assert.That(tamperedSignature.Outcome, Is.EqualTo(DeviceRegistrationOutcome.InvalidProof));
            Assert.That(valid.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
        });
    }

    [Test]
    public async Task Concurrent_replay_creates_exactly_one_device()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var issued = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key),
            CancellationToken.None);
        var completion = new CompleteDeviceRegistrationRequest(
            issued.Challenge!.SigningInput,
            Sign(key, Decode(issued.Challenge.SigningInput)));

        var attempts = await Task.WhenAll(
            fixture.Service.CompleteAsync(
                "consumer-A",
                issued.Challenge.ChallengeId,
                completion,
                CancellationToken.None),
            fixture.Service.CompleteAsync(
                "consumer-A",
                issued.Challenge.ChallengeId,
                completion,
                CancellationToken.None));
        var devices = await fixture.Service.ListAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(attempts.Count(result => result.Outcome == DeviceRegistrationOutcome.Succeeded), Is.EqualTo(1));
            Assert.That(attempts.Count(result => result.Outcome == DeviceRegistrationOutcome.Conflict), Is.EqualTo(1));
            Assert.That(devices, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task One_public_key_cannot_bind_multiple_devices_or_consumers()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var first = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key, "First"),
            CancellationToken.None);
        var second = await fixture.Service.IssueChallengeAsync(
            "consumer-B",
            StartRequest(key, "Second"),
            CancellationToken.None);

        var firstCompletion = await Complete(fixture.Service, "consumer-A", first.Challenge!, key);
        var secondCompletion = await Complete(fixture.Service, "consumer-B", second.Challenge!, key);
        var secondOwnerDevices = await fixture.Service.ListAsync("consumer-B", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(firstCompletion.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(secondCompletion.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Conflict));
            Assert.That(secondOwnerDevices, Is.Empty);
        });
    }

    [Test]
    public async Task Revocation_is_owner_bound_terminal_and_idempotent()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var issued = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(key),
            CancellationToken.None);
        var registered = await Complete(fixture.Service, "consumer-A", issued.Challenge!, key);

        var wrongOwner = await fixture.Service.RevokeAsync(
            "consumer-B",
            registered.Device!.DeviceId,
            CancellationToken.None);
        var revoked = await fixture.Service.RevokeAsync(
            "consumer-A",
            registered.Device.DeviceId,
            CancellationToken.None);
        var repeated = await fixture.Service.RevokeAsync(
            "consumer-A",
            registered.Device.DeviceId,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(wrongOwner.Outcome, Is.EqualTo(DeviceRegistrationOutcome.NotFound));
            Assert.That(revoked.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(revoked.Device!.RevocationState, Is.EqualTo(DeviceRevocationState.Revoked));
            Assert.That(repeated.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(repeated.Device, Is.EqualTo(revoked.Device));
        });
    }

    [Test]
    public async Task Revoking_a_device_frees_active_capacity_for_its_replacement()
    {
        using var firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var replacementKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var policy = DeviceRegistrationPolicy.Default with
        {
            MaximumDevices = 1,
            MaximumRetainedDevices = 1
        };
        var fixture = Fixture(policy);
        var first = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(firstKey, "First browser"),
            CancellationToken.None);
        var registered = await Complete(fixture.Service, "consumer-A", first.Challenge!, firstKey);
        _ = await fixture.Service.RevokeAsync(
            "consumer-A",
            registered.Device!.DeviceId,
            CancellationToken.None);

        var replacement = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            StartRequest(replacementKey, "Replacement browser"),
            CancellationToken.None);
        var completed = await Complete(
            fixture.Service,
            "consumer-A",
            replacement.Challenge!,
            replacementKey);
        var devices = await fixture.Service.ListAsync("consumer-A", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(replacement.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(completed.Outcome, Is.EqualTo(DeviceRegistrationOutcome.Succeeded));
            Assert.That(devices, Has.Count.EqualTo(1));
            Assert.That(devices.Single().FriendlyName, Is.EqualTo("Replacement browser"));
            Assert.That(devices.Single().RevocationState, Is.EqualTo(DeviceRevocationState.Active));
        });
    }

    [Test]
    public async Task Private_keys_and_unbounded_metadata_are_rejected_before_persistence()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = Fixture();
        var request = new StartDeviceRegistrationRequest(
            new string('x', DeviceRegistrationPolicy.Default.MaximumFriendlyNameUtf8Bytes + 1),
            DevicePlatformType.BrowserExtension,
            "1.0",
            Es256DeviceProofVerifier.Algorithm,
            Encode(key.ExportPkcs8PrivateKey()));

        var result = await fixture.Service.IssueChallengeAsync(
            "consumer-A",
            request,
            CancellationToken.None);
        var stored = await fixture.Repository.GetAsync(
            fixture.KeyDerivation.OwnerScopeId("consumer-A"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Outcome, Is.EqualTo(DeviceRegistrationOutcome.InvalidRequest));
            Assert.That(stored, Is.Null);
        });
    }

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

    private static ServiceFixture Fixture(DeviceRegistrationPolicy? policy = null)
    {
        var clock = new MutableTimeProvider(Now);
        var repository = new CapturingDeviceRegistrationRepository();
        var keyDerivation = new DeviceRegistrationKeyDerivation(new PrivacyHashingOptions(
            "hip-device-registration-tests-exact-key",
            AllowDevelopmentKey: true));
        var service = new DeviceRegistrationService(
            repository,
            new Es256DeviceProofVerifier(),
            new Rfc8785CanonicalJsonService(),
            keyDerivation,
            new AuditLogService(new InMemoryAuditLogRepository()),
            clock,
            policy ?? DeviceRegistrationPolicy.Default);
        return new ServiceFixture(service, repository, keyDerivation, clock);
    }

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

    private sealed record ServiceFixture(
        IDeviceRegistrationService Service,
        CapturingDeviceRegistrationRepository Repository,
        DeviceRegistrationKeyDerivation KeyDerivation,
        MutableTimeProvider Clock);

    private sealed class CapturingDeviceRegistrationRepository : IDeviceRegistrationRepository
    {
        private readonly InMemoryDeviceRegistrationRepository inner = new();
        private readonly List<AuditLogEntry> auditEntries = [];

        public IReadOnlyCollection<AuditLogEntry> AuditEntries => auditEntries;

        public Task<DeviceRegistrationAggregate?> GetAsync(
            string ownerScopeId,
            CancellationToken cancellationToken) =>
            inner.GetAsync(ownerScopeId, cancellationToken);

        public Task<RegisteredDevice?> GetDeviceAsync(
            string deviceId,
            CancellationToken cancellationToken) =>
            inner.GetDeviceAsync(deviceId, cancellationToken);

        public async Task<DeviceRegistrationSaveOutcome> TrySaveAsync(
            DeviceRegistrationTransitionBatch transition,
            CancellationToken cancellationToken)
        {
            var outcome = await inner.TrySaveAsync(transition, cancellationToken);
            if (outcome == DeviceRegistrationSaveOutcome.Succeeded)
            {
                auditEntries.AddRange(transition.AuditEntries);
            }

            return outcome;
        }
    }
    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }
}
