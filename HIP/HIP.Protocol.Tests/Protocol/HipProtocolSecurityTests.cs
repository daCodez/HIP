using System.Security.Cryptography;
using HIP.Protocol.Canonicalization;
using HIP.Protocol.Contracts;
using HIP.Protocol.Security.Options;
using HIP.Protocol.Security.Services;
using HIP.Protocol.Validation;
using HIP.Protocol.Versioning;

namespace HIP.Protocol.Tests.Protocol;

public class HipProtocolSecurityTests
{
    private readonly HipCanonicalSerializer _canonical = new();
    private readonly Sha256PayloadHasher _hasher = new();

    [Test]
    public async Task ValidEnvelope_ShouldVerify()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelope("key-sender", "hello");

        var result = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(result.Success, Is.EqualTo(true));
    }

    [Test]
    public async Task InvalidSignature_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelope("key-sender", "hello") with { Signature = "bad-signature" };

        var result = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.InvalidSignature));
    }

    [Test]
    public async Task ExpiredTimestamp_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier(skewSeconds: 5);
        var envelope = BuildSignedEnvelope("key-sender", "hello", DateTimeOffset.UtcNow.AddMinutes(-10));

        var result = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.TimestampExpired));
    }

    [Test]
    public async Task ReplayedNonce_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelope("key-sender", "hello");

        var first = await svc.VerifyAsync(envelope, "key-sender");
        var second = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(first.Success, Is.EqualTo(true));
        Assert.That(second.Success, Is.EqualTo(false));
        Assert.That(second.Error?.Code, Is.EqualTo(HipErrorCode.ReplayDetected));
    }

    [Test]
    public async Task UnsupportedVersion_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var signed = BuildSignedEnvelope("key-sender", "hello");
        var wrong = signed with { HipVersion = "2.0" };

        var result = await svc.VerifyAsync(wrong, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.UnsupportedVersion));
    }

    [Test]
    public async Task DowngradeVersion_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var signed = BuildSignedEnvelope("key-sender", "hello");
        var downgraded = signed with { HipVersion = "0.9" };

        var result = await svc.VerifyAsync(downgraded, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.UnsupportedVersion));
    }

    [Test]
    public async Task VersionPolicy_ShouldAllowConfiguredVersion()
    {
        var signer = BuildSigner();
        var versionPolicy = new HipVersionPolicy(["1.1"]);
        var svc = new HipEnvelopeSecurityService(_canonical, new HipEnvelopeValidator(), signer, signer,
            new InMemoryReplayGuard(new HipSecurityOptions()), new HipTimestampPolicy(new HipSecurityOptions()), new NoopRevocationChecker(), versionPolicy);

        var envelope = BuildSignedEnvelope("key-sender", "hello") with { HipVersion = "1.1" };
        var canonical = _canonical.CanonicalizeEnvelope(envelope with { Signature = string.Empty });
        envelope = envelope with { Signature = signer.Sign(canonical, "key-sender") };

        var result = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(result.Success, Is.EqualTo(true));
    }

    [Test]
    public async Task MissingRequiredField_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelope("key-sender", "hello") with { Nonce = string.Empty };

        var result = await svc.VerifyAsync(envelope, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.InvalidEnvelope));
    }

    [Test]
    public void InvalidTrustReceiptSignature_ShouldFail()
    {
        var signer = BuildSigner();
        var service = new HipReceiptSecurityService(_canonical, new HipReceiptValidator(), signer, signer);

        var issued = service.Issue(BuildUnsignedReceipt(), "key-verifier");
        var tampered = issued with { ReceiptSignature = "bad" };

        var result = service.Verify(tampered, "key-verifier");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.InvalidSignature));
    }

    [Test]
    public async Task CanonicalSerializationMismatch_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelope("key-sender", "hello");
        var tampered = envelope with { CorrelationId = envelope.CorrelationId + "-changed" };

        var result = await svc.VerifyAsync(tampered, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.InvalidSignature));
    }

    [Test]
    public async Task ExtensionConfusion_TamperedExtension_ShouldFail()
    {
        var svc = BuildEnvelopeVerifier();
        var envelope = BuildSignedEnvelopeWithExtensions("key-sender", "hello", new Dictionary<string, string>
        {
            ["ext.intent"] = "payment",
            ["ext.channel"] = "chat"
        });

        var tampered = envelope with
        {
            Extensions = new Dictionary<string, string>
            {
                ["ext.intent"] = "admin-override",
                ["ext.channel"] = "chat"
            }
        };

        var result = await svc.VerifyAsync(tampered, "key-sender");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.InvalidSignature));
    }

    [Test]
    public void ChallengeSuccess_ShouldPass()
    {
        var signer = BuildSigner();
        var challengeSvc = new HipChallengeService(signer, signer);
        var challenge = challengeSvc.CreateChallenge("sender-1", "verifier-1");
        var proof = challengeSvc.CreateProof(challenge, "sender-1", "key-sender");

        var ok = challengeSvc.VerifyProof(challenge, proof, "key-sender");

        Assert.That(ok, Is.EqualTo(true));
    }

    [Test]
    public void ChallengeFail_ShouldFail()
    {
        var signer = BuildSigner();
        var challengeSvc = new HipChallengeService(signer, signer);
        var challenge = challengeSvc.CreateChallenge("sender-1", "verifier-1");
        var proof = challengeSvc.CreateProof(challenge, "sender-1", "key-sender") with { Signature = "bad" };

        var ok = challengeSvc.VerifyProof(challenge, proof, "key-sender");

        Assert.That(ok, Is.EqualTo(false));
    }

    [Test]
    public async Task RevokedKey_ShouldFail()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new HIP.Protocol.Security.Abstractions.HipSigningKey("sender-ecdsa", "ECDSA_P256_SHA256", ecdsa, Revoked: true);
        var keyStore = new InMemoryHipKeyStore([key]);
        var router = new AlgorithmRouterSigner(keyStore, [new EcdsaP256AlgorithmProvider()]);

        var envelope = BuildSignedEnvelopeWith(router, "sender-ecdsa", "hello");
        var svc = new HipEnvelopeSecurityService(_canonical, new HipEnvelopeValidator(), router, router,
            new InMemoryReplayGuard(new HipSecurityOptions()), new HipTimestampPolicy(new HipSecurityOptions()), new NoopRevocationChecker(), keyStore: keyStore, keyLifecycleValidator: new HipKeyLifecycleValidator());

        var result = await svc.VerifyAsync(envelope, "sender-ecdsa");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.KeyRevoked));
    }

    [Test]
    public async Task RotatedOutKey_ShouldFail_WhenExpired()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new HIP.Protocol.Security.Abstractions.HipSigningKey("sender-ecdsa", "ECDSA_P256_SHA256", ecdsa,
            NotBeforeUtc: DateTimeOffset.UtcNow.AddHours(-2), NotAfterUtc: DateTimeOffset.UtcNow.AddHours(-1), ReplacedByKeyId: "sender-ecdsa-v2");
        var keyStore = new InMemoryHipKeyStore([key]);
        var router = new AlgorithmRouterSigner(keyStore, [new EcdsaP256AlgorithmProvider()]);

        var envelope = BuildSignedEnvelopeWith(router, "sender-ecdsa", "hello", DateTimeOffset.UtcNow);
        var svc = new HipEnvelopeSecurityService(_canonical, new HipEnvelopeValidator(), router, router,
            new InMemoryReplayGuard(new HipSecurityOptions()), new HipTimestampPolicy(new HipSecurityOptions()), new NoopRevocationChecker(), keyStore: keyStore, keyLifecycleValidator: new HipKeyLifecycleValidator());

        var result = await svc.VerifyAsync(envelope, "sender-ecdsa");

        Assert.That(result.Success, Is.EqualTo(false));
        Assert.That(result.Error?.Code, Is.EqualTo(HipErrorCode.KeyRevoked));
    }

    [Test]
    public async Task Ed25519Envelope_ShouldVerify()
    {
        var material = Ed25519KeyMaterial.Generate();
        var key = new HIP.Protocol.Security.Abstractions.HipSigningKey("sender-ed25519", "ED25519", material);
        var keyStore = new InMemoryHipKeyStore([key]);
        var router = new AlgorithmRouterSigner(keyStore, [new Ed25519AlgorithmProvider()]);

        var envelope = BuildSignedEnvelopeWith(router, "sender-ed25519", "hello-ed25519", DateTimeOffset.UtcNow);
        var svc = new HipEnvelopeSecurityService(_canonical, new HipEnvelopeValidator(), router, router,
            new InMemoryReplayGuard(new HipSecurityOptions()), new HipTimestampPolicy(new HipSecurityOptions()), new NoopRevocationChecker(), keyStore: keyStore, keyLifecycleValidator: new HipKeyLifecycleValidator());

        var result = await svc.VerifyAsync(envelope, "sender-ed25519");

        Assert.That(result.Success, Is.EqualTo(true));
    }

    private HipEnvelopeSecurityService BuildEnvelopeVerifier(int skewSeconds = 300)
    {
        var signer = BuildSigner();
        return new HipEnvelopeSecurityService(
            _canonical,
            new HipEnvelopeValidator(),
            signer,
            signer,
            new InMemoryReplayGuard(new HipSecurityOptions { AllowedClockSkewSeconds = skewSeconds, ReplayWindowSeconds = 600 }),
            new HipTimestampPolicy(new HipSecurityOptions { AllowedClockSkewSeconds = skewSeconds, ReplayWindowSeconds = 600 }),
            new NoopRevocationChecker());
    }

    private HmacHipSigner BuildSigner()
        => new(new Dictionary<string, string>
        {
            ["key-sender"] = "sender-secret-123",
            ["key-verifier"] = "verifier-secret-456"
        });

    private HipMessageEnvelope BuildSignedEnvelope(string keyId, string payload, DateTimeOffset? timestamp = null)
    {
        var signer = BuildSigner();
        var envelope = new HipMessageEnvelope(
            HipProtocolVersions.V1,
            "ProtectedHttpRequest",
            "key-sender",
            "receiver-a",
            timestamp ?? DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString("N"),
            _hasher.ComputePayloadHash(payload),
            string.Empty,
            Guid.NewGuid().ToString("N"));

        var canonical = _canonical.CanonicalizeEnvelope(envelope with { Signature = string.Empty });
        var signature = signer.Sign(canonical, keyId);
        return envelope with { Signature = signature };
    }

    private HipMessageEnvelope BuildSignedEnvelopeWith(HIP.Protocol.Security.Abstractions.IHipSigner signer, string keyId, string payload, DateTimeOffset? timestamp = null)
    {
        var envelope = new HipMessageEnvelope(
            HipProtocolVersions.V1,
            "ProtectedHttpRequest",
            keyId,
            "receiver-a",
            timestamp ?? DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString("N"),
            _hasher.ComputePayloadHash(payload),
            string.Empty,
            Guid.NewGuid().ToString("N"));

        var canonical = _canonical.CanonicalizeEnvelope(envelope with { Signature = string.Empty });
        var signature = signer.Sign(canonical, keyId);
        return envelope with { Signature = signature };
    }

    private HipMessageEnvelope BuildSignedEnvelopeWithExtensions(string keyId, string payload, IReadOnlyDictionary<string, string> extensions)
    {
        var signer = BuildSigner();
        var envelope = new HipMessageEnvelope(
            HipProtocolVersions.V1,
            "ProtectedHttpRequest",
            "key-sender",
            "receiver-a",
            DateTimeOffset.UtcNow,
            Guid.NewGuid().ToString("N"),
            _hasher.ComputePayloadHash(payload),
            string.Empty,
            Guid.NewGuid().ToString("N"),
            Extensions: new Dictionary<string, string>(extensions));

        var canonical = _canonical.CanonicalizeEnvelope(envelope with { Signature = string.Empty });
        var signature = signer.Sign(canonical, keyId);
        return envelope with { Signature = signature };
    }

    private HipTrustReceipt BuildUnsignedReceipt()
        => new(
            ReceiptId: Guid.NewGuid().ToString("N"),
            HipVersion: HipProtocolVersions.V1,
            InteractionType: "ProtectedHttpRequest",
            SenderHipId: "key-sender",
            ReceiverHipId: "receiver-a",
            TimestampUtc: DateTimeOffset.UtcNow,
            MessageHash: _hasher.ComputePayloadHash("hello"),
            DeviceId: null,
            Checks: ["signature", "nonce", "timestamp"],
            Decision: HipDecision.Allow,
            AppliedPolicyIds: ["policy-1"],
            ReputationSnapshot: 80,
            ReceiptSignature: string.Empty);
}
