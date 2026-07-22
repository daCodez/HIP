using System.Security.Cryptography;
using HIP.Application.Devices;
using HIP.Application.Security;
using HIP.Domain.Devices;

namespace HIP.Tests.Devices;

[TestFixture]
public sealed class DeviceRequestProofServiceTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_752_969_600);

    [Test]
    public async Task Accepts_once_and_rejects_replay_for_active_registered_device()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(key, DeviceRevocationState.Active);
        var body = new ProofBody("Safe", new NestedBody(90, true));
        var proof = CreateProof(key, fixture.Device.DeviceId, body, Now, "BwcHBwcHBwcHBwcHBwcHBwcH");

        var accepted = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/scan-results", body, CancellationToken.None);
        var replayed = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/scan-results", body, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(accepted.Status, Is.EqualTo(DeviceRequestProofStatus.Accepted));
            Assert.That(replayed.Status, Is.EqualTo(DeviceRequestProofStatus.Replayed));
            Assert.That(proof.BodyDigest, Is.EqualTo(
                "sha256:4f3909aad65b83ebe6ad7379d41e0eabec2b8c508fa6172c2465c9196c1216aa"));
        });
    }

    [Test]
    public async Task Rejects_body_path_signature_and_timestamp_tampering_without_reserving_nonce()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(key, DeviceRevocationState.Active);
        var body = new ProofBody("Safe", new NestedBody(90, true));
        var proof = CreateProof(key, fixture.Device.DeviceId, body, Now, "CAgICAgICAgICAgICAgICAgI");

        var changedBody = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/scan-results", body with { Status = "Dangerous" }, CancellationToken.None);
        var changedPath = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/other", body, CancellationToken.None);
        var expiredProof = CreateProof(
            key, fixture.Device.DeviceId, body, Now.Subtract(TimeSpan.FromMinutes(6)), "CQkJCQkJCQkJCQkJCQkJCQkJ");
        var expired = await fixture.Service.ValidateAndReserveAsync(
            expiredProof, "POST", "/api/v1/browser/scan-results", body, CancellationToken.None);
        var validAfterFailures = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/scan-results", body, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(changedBody.Status, Is.EqualTo(DeviceRequestProofStatus.Invalid));
            Assert.That(changedPath.Status, Is.EqualTo(DeviceRequestProofStatus.Invalid));
            Assert.That(expired.Status, Is.EqualTo(DeviceRequestProofStatus.Expired));
            Assert.That(validAfterFailures.Status, Is.EqualTo(DeviceRequestProofStatus.Accepted));
        });
    }

    [Test]
    public async Task Revoked_device_fails_closed_and_never_becomes_authoritative()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = CreateFixture(key, DeviceRevocationState.Revoked);
        var body = new ProofBody("Safe", new NestedBody(90, true));
        var proof = CreateProof(key, fixture.Device.DeviceId, body, Now, "CgoKCgoKCgoKCgoKCgoKCgoK");

        var result = await fixture.Service.ValidateAndReserveAsync(
            proof, "POST", "/api/v1/browser/scan-results", body, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(DeviceRequestProofStatus.Revoked));
    }

    private static Fixture CreateFixture(ECDsa key, DeviceRevocationState state)
    {
        var verifier = new Es256DeviceProofVerifier();
        var publicKey = verifier.ValidatePublicKey(
            Es256DeviceProofVerifier.Algorithm,
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        var device = new RegisteredDevice(
            "dev_browser_test",
            "HIP browser extension",
            DevicePlatformType.BrowserExtension,
            "0.1.14",
            publicKey.Algorithm,
            publicKey.PublicKey,
            publicKey.PublicKeyFingerprint,
            DeviceTrustState.ProofOfPossessionVerified,
            state,
            Now.AddDays(-1),
            Now.AddMinutes(-1),
            state == DeviceRevocationState.Revoked ? Now.AddSeconds(-1) : null);
        var service = new DeviceRequestProofService(
            new StubRepository(device),
            verifier,
            new InMemoryReplayNonceStore(new FixedTimeProvider(Now)),
            new FixedTimeProvider(Now));
        return new Fixture(service, device);
    }

    private static DeviceRequestProof CreateProof(
        ECDsa key,
        string deviceId,
        ProofBody body,
        DateTimeOffset timestamp,
        string nonce)
    {
        var timestampValue = timestamp.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var digest = DeviceRequestProofCanonicalizer.BodyDigest(body);
        var signingInput = DeviceRequestProofCanonicalizer.SigningInput(
            deviceId, "POST", "/api/v1/browser/scan-results", digest, timestampValue, nonce);
        var signature = key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new DeviceRequestProof(
            deviceId,
            timestampValue,
            nonce,
            digest,
            Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
    }

    private sealed record ProofBody(string Status, NestedBody Nested);
    private sealed record NestedBody(int Score, bool Active);
    private sealed record Fixture(DeviceRequestProofService Service, RegisteredDevice Device);

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class StubRepository(RegisteredDevice device) : IDeviceRegistrationRepository
    {
        public Task<RegisteredDevice?> GetDeviceAsync(string deviceId, CancellationToken cancellationToken) =>
            Task.FromResult<RegisteredDevice?>(string.Equals(deviceId, device.DeviceId, StringComparison.Ordinal) ? device : null);

        public Task<DeviceRegistrationAggregate?> GetAsync(string ownerScopeId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DeviceRegistrationSaveOutcome> TrySaveAsync(DeviceRegistrationTransitionBatch transition, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
