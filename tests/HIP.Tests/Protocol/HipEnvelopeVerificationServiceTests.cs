using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Application.Security;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Protocol;

public sealed class HipEnvelopeVerificationServiceTests
{
    private const string IdentityId = "hip:web:envelope.example";
    private const string InitialKeyId = "key-1";
    private const string NonceOne = "AAECAwQFBgcICQoLDA0ODw";
    private const string NonceTwo = "EBESExQVFhcYGRobHB0eHw";
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ActivatedAt = Now.AddMinutes(-2);

    [Test]
    public async Task Valid_envelope_is_accepted_without_implying_safety_or_reputation()
    {
        var fixture = await CreateFixtureAsync();
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));

        var result = await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.Accepted));
            Assert.That(result.IsAccepted, Is.True);
            Assert.That(result.VerifiedIssuerId, Is.EqualTo(IdentityId));
            Assert.That(result.VerifiedKeyId, Is.EqualTo(InitialKeyId));
            Assert.That(result.EstablishesSafetyOrReputation, Is.False);
        });
    }

    [Test]
    public async Task Malformed_and_unsupported_envelopes_fail_before_state_or_replay_work()
    {
        var replay = new CountingReplayProtectionService();
        var service = Service(
            new HipSignedDocumentVerifier(
                new ThrowingSigningKeyLifecycleRepository(),
                new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]),
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new Rfc8785CanonicalJsonService()),
            replay);
        var valid = HipProtocolEnvelopeJson.Serialize(CreateEnvelope(new DevelopmentHipCryptoProvider()));
        var unsupported = valid.Replace("\"version\":\"1.0\"", "\"version\":\"2.0\"", StringComparison.Ordinal);
        var invalidDigest = valid.Replace("\"contentDigest\":{\"algorithm\":\"sha256\"", "\"contentDigest\":{\"algorithm\":\"sha512\"", StringComparison.Ordinal);

        var malformedResult = await service.VerifyAsync(Encoding.UTF8.GetBytes("{"), CancellationToken.None);
        var unsupportedResult = await service.VerifyAsync(Encoding.UTF8.GetBytes(unsupported), CancellationToken.None);
        var invalidDigestResult = await service.VerifyAsync(Encoding.UTF8.GetBytes(invalidDigest), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(malformedResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.MalformedEnvelope));
            Assert.That(unsupportedResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.UnsupportedVersion));
            Assert.That(invalidDigestResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.MalformedEnvelope));
            Assert.That(replay.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Expired_envelope_fails_before_identity_crypto_or_replay_work()
    {
        var replay = new CountingReplayProtectionService();
        var providerFactory = new RecordingSignatureProviderFactory(
            new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]));
        var service = Service(
            new HipSignedDocumentVerifier(
                new ThrowingSigningKeyLifecycleRepository(),
                providerFactory,
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new Rfc8785CanonicalJsonService()),
            replay);
        var envelope = CreateEnvelope(
            new DevelopmentHipCryptoProvider(),
            issuedAtUtc: Now.AddMinutes(-2),
            expiresAtUtc: Now.AddMilliseconds(-1));

        var result = await service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.Expired));
            Assert.That(providerFactory.RequestedAlgorithms, Is.Empty);
            Assert.That(replay.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Issuer_lookup_requires_an_exact_verified_canonical_binding()
    {
        var fixture = await CreateFixtureAsync();
        var caseMismatched = fixture.Sign(Copy(
            CreateEnvelope(fixture.Provider),
            issuer: new HipProtocolIssuer(IdentityId.ToUpperInvariant())));
        var unknown = fixture.Sign(Copy(
            CreateEnvelope(fixture.Provider, messageId: "msg-unknown", nonce: NonceTwo),
            issuer: new HipProtocolIssuer("hip:web:unknown.example")));

        var caseResult = await fixture.Service.VerifyAsync(Json(caseMismatched), CancellationToken.None);
        var unknownResult = await fixture.Service.VerifyAsync(Json(unknown), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(caseResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.IssuerBindingMismatch));
            Assert.That(unknownResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.IssuerNotFound));
        });
    }

    [TestCase(VerificationStatus.Unverified)]
    [TestCase(VerificationStatus.Pending)]
    [TestCase(VerificationStatus.Suspended)]
    [TestCase(VerificationStatus.Revoked)]
    public async Task Non_verified_issuers_cannot_authorize_envelope_claims(VerificationStatus issuerStatus)
    {
        var fixture = await CreateFixtureAsync(issuerStatus: issuerStatus);
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));

        var result = await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(issuerStatus switch
        {
            VerificationStatus.Suspended => HipEnvelopeVerificationStatus.IssuerSuspended,
            VerificationStatus.Revoked => HipEnvelopeVerificationStatus.IssuerRevoked,
            _ => HipEnvelopeVerificationStatus.IssuerNotVerified
        }));
    }

    [Test]
    public async Task Key_and_signature_metadata_must_match_authoritative_lifecycle_state()
    {
        var fixture = await CreateFixtureAsync();
        var unknownKey = fixture.Sign(Copy(
            CreateEnvelope(fixture.Provider),
            signature: Signature(fixture.Provider, keyId: "unknown-key")));
        var attackerAlgorithm = fixture.Sign(Copy(
            CreateEnvelope(fixture.Provider, messageId: "msg-algorithm", nonce: NonceTwo),
            signature: Signature(fixture.Provider, algorithm: "attacker-selected")));
        var familyMismatch = fixture.Sign(Copy(
            CreateEnvelope(fixture.Provider, messageId: "msg-family", nonce: "ICEiIyQlJicoKSorLC0uLw"),
            signature: Signature(fixture.Provider, family: SignatureAlgorithmFamily.PostQuantum)));

        var unknownKeyResult = await fixture.Service.VerifyAsync(Json(unknownKey), CancellationToken.None);
        var algorithmResult = await fixture.Service.VerifyAsync(Json(attackerAlgorithm), CancellationToken.None);
        var familyResult = await fixture.Service.VerifyAsync(Json(familyMismatch), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(unknownKeyResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.KeyNotFound));
            Assert.That(algorithmResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.SignatureMetadataMismatch));
            Assert.That(familyResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.SignatureMetadataMismatch));
            Assert.That(fixture.ProviderFactory.RequestedAlgorithms, Has.Count.EqualTo(2));
            Assert.That(fixture.ProviderFactory.RequestedAlgorithms, Is.All.EqualTo(DevelopmentHipCryptoProvider.Algorithm));
        });
    }

    [Test]
    public async Task Production_policy_rejects_an_unavailable_provider_without_reserving_replay_state()
    {
        var fixture = await CreateFixtureAsync();
        var replay = new CountingReplayProtectionService();
        var core = new HipSignedDocumentVerifier(
            fixture.Repository,
            new HipSignatureProviderFactory([fixture.Provider]),
            SignatureProviderRuntimePolicy.ForProduction(MlDsa65SignatureProvider.Algorithm),
            new Rfc8785CanonicalJsonService());
        var service = Service(core, replay);
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));

        var result = await service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.ProviderUnavailable));
            Assert.That(replay.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Unexpected_provider_and_canonicalizer_failures_are_typed_and_do_not_reserve_replay_state()
    {
        var fixture = await CreateFixtureAsync();
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));
        var providerReplay = new CountingReplayProtectionService();
        var providerService = Service(
            new HipSignedDocumentVerifier(
                fixture.Repository,
                new HipSignatureProviderFactory([new ThrowingVerificationSignatureProvider(fixture.Provider)]),
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new Rfc8785CanonicalJsonService()),
            providerReplay);
        var canonicalizerReplay = new CountingReplayProtectionService();
        var canonicalizerService = Service(
            new HipSignedDocumentVerifier(
                fixture.Repository,
                new HipSignatureProviderFactory([fixture.Provider]),
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new ThrowingCanonicalJsonService()),
            canonicalizerReplay);

        var providerResult = await providerService.VerifyAsync(Json(envelope), CancellationToken.None);
        var canonicalizerResult = await canonicalizerService.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(providerResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.ProviderUnavailable));
            Assert.That(canonicalizerResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.VerificationStateUnavailable));
            Assert.That(providerReplay.CallCount, Is.Zero);
            Assert.That(canonicalizerReplay.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Every_signed_envelope_field_is_tamper_evident_and_invalid_attempts_do_not_poison_replay_state()
    {
        var replay = new CountingReplayProtectionService();
        var fixture = await CreateFixtureAsync(replayProtectionService: replay);
        var original = fixture.Sign(CreateEnvelope(fixture.Provider));
        var tampered = new[]
        {
            Copy(original, messageId: "msg-tampered"),
            Copy(original, nonce: NonceTwo),
            Copy(original, subject: new HipProtocolSubject(IdentitySubjectType.Website, "other.example")),
            Copy(original, contentDigest: new HipContentDigest("sha256", new string('b', 64))),
            Copy(original, claims: Claims("different")),
            Copy(original, issuedAtUtc: original.IssuedAtUtc.AddMilliseconds(1)),
            Copy(original, expiresAtUtc: original.ExpiresAtUtc.AddMilliseconds(1)),
            Copy(original, signature: Signature(fixture.Provider, value: "malformed-signature"))
        };

        var results = new List<HipEnvelopeVerificationResult>();
        foreach (var envelope in tampered)
        {
            results.Add(await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None));
        }
        var validResult = await fixture.Service.VerifyAsync(Json(original), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(results.Select(result => result.Status), Is.All.EqualTo(HipEnvelopeVerificationStatus.InvalidSignature));
            Assert.That(validResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.Accepted));
            Assert.That(replay.CallCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Retired_key_accepts_pre_rotation_signature_and_rejects_the_exclusive_cutoff()
    {
        var fixture = await CreateFixtureAsync();
        var cutoff = Now.AddMinutes(-1);
        var replacement = fixture.Provider.GenerateKeyPair();
        var rotation = await fixture.Lifecycle.RotateAsync(
            new RotateSigningKeyRequest(
                IdentityId,
                InitialKeyId,
                1,
                "key-2",
                replacement.Algorithm,
                replacement.PublicKey,
                "security-operator",
                "Scheduled key rotation",
                cutoff),
            CancellationToken.None);
        await fixture.Lifecycle.RetireAsync(
            new ChangeSigningKeyStateRequest(
                IdentityId,
                InitialKeyId,
                rotation.KeyRing.Version,
                "security-operator",
                "Complete rotation",
                cutoff.AddSeconds(30)),
            CancellationToken.None);
        var beforeCutoff = fixture.Sign(CreateEnvelope(
            fixture.Provider,
            messageId: "msg-before-cutoff",
            nonce: NonceOne,
            issuedAtUtc: cutoff.AddMilliseconds(-1)));
        var atCutoff = fixture.Sign(CreateEnvelope(
            fixture.Provider,
            messageId: "msg-at-cutoff",
            nonce: NonceTwo,
            issuedAtUtc: cutoff));

        var beforeResult = await fixture.Service.VerifyAsync(Json(beforeCutoff), CancellationToken.None);
        var cutoffResult = await fixture.Service.VerifyAsync(Json(atCutoff), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(beforeResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.Accepted));
            Assert.That(cutoffResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.KeyNotValidAtIssuedTime));
        });
    }

    [Test]
    public async Task Revoked_key_cannot_verify_even_a_pre_revocation_signature()
    {
        var fixture = await CreateFixtureAsync();
        var replacement = fixture.Provider.GenerateKeyPair();
        await fixture.Lifecycle.EmergencyReplaceAsync(
            new EmergencyReplaceSigningKeyRequest(
                IdentityId,
                InitialKeyId,
                1,
                "emergency-key",
                replacement.Algorithm,
                replacement.PublicKey,
                "security-operator",
                "Compromise response",
                Now.AddMinutes(-1)),
            CancellationToken.None);
        var envelope = fixture.Sign(CreateEnvelope(
            fixture.Provider,
            issuedAtUtc: Now.AddMinutes(-1).AddMilliseconds(-1)));

        var result = await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.KeyRevoked));
    }

    [Test]
    public async Task Replay_outcomes_are_typed_and_only_follow_valid_signatures()
    {
        var fixture = await CreateFixtureAsync();
        var first = fixture.Sign(CreateEnvelope(fixture.Provider));
        var sameNonce = fixture.Sign(CreateEnvelope(
            fixture.Provider,
            messageId: "msg-second",
            nonce: NonceOne));

        var accepted = await fixture.Service.VerifyAsync(Json(first), CancellationToken.None);
        var duplicateMessage = await fixture.Service.VerifyAsync(Json(first), CancellationToken.None);
        var duplicateNonce = await fixture.Service.VerifyAsync(Json(sameNonce), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(accepted.Status, Is.EqualTo(HipEnvelopeVerificationStatus.Accepted));
            Assert.That(duplicateMessage.Status, Is.EqualTo(HipEnvelopeVerificationStatus.DuplicateMessageId));
            Assert.That(duplicateNonce.Status, Is.EqualTo(HipEnvelopeVerificationStatus.DuplicateNonce));
        });
    }

    [TestCase(
        HipReplayProtectionStatus.TimestampOutsideTolerance,
        HipEnvelopeVerificationStatus.TimestampOutsideTolerance)]
    [TestCase(
        HipReplayProtectionStatus.ValidityWindowExceeded,
        HipEnvelopeVerificationStatus.ValidityWindowExceeded)]
    [TestCase(
        HipReplayProtectionStatus.Unspecified,
        HipEnvelopeVerificationStatus.ReplayStateUnavailable)]
    public async Task Replay_policy_outcomes_map_to_public_fail_closed_statuses(
        HipReplayProtectionStatus replayStatus,
        HipEnvelopeVerificationStatus expectedStatus)
    {
        var fixture = await CreateFixtureAsync(new FixedReplayProtectionService(replayStatus));
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));

        var result = await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(expectedStatus));
    }

    [Test]
    public async Task Replay_and_identity_state_failures_fail_closed_without_exception_details()
    {
        var fixture = await CreateFixtureAsync(new FixedReplayProtectionService(HipReplayProtectionStatus.StateUnavailable));
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));
        var replayResult = await fixture.Service.VerifyAsync(Json(envelope), CancellationToken.None);
        var stateService = Service(
            new HipSignedDocumentVerifier(
                new ThrowingSigningKeyLifecycleRepository(),
                new HipSignatureProviderFactory([fixture.Provider]),
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new Rfc8785CanonicalJsonService()),
            new CountingReplayProtectionService());
        var identityResult = await stateService.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(replayResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.ReplayStateUnavailable));
            Assert.That(identityResult.Status, Is.EqualTo(HipEnvelopeVerificationStatus.VerificationStateUnavailable));
            Assert.That(identityResult.ToString(), Does.Not.Contain("simulated repository failure"));
        });
    }

    [Test]
    public void Pre_cancellation_propagates_without_touching_state()
    {
        var replay = new CountingReplayProtectionService();
        var service = Service(
            new HipSignedDocumentVerifier(
                new ThrowingSigningKeyLifecycleRepository(),
                new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]),
                SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
                new Rfc8785CanonicalJsonService()),
            replay);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(() =>
            service.VerifyAsync(Encoding.UTF8.GetBytes("{}"), cancellation.Token));
        Assert.That(replay.CallCount, Is.Zero);
    }

    [Test]
    public async Task Cancellation_during_replay_propagates_after_valid_crypto()
    {
        var replay = new BlockingReplayProtectionService();
        var fixture = await CreateFixtureAsync(replayProtectionService: replay);
        var envelope = fixture.Sign(CreateEnvelope(fixture.Provider));
        using var cancellation = new CancellationTokenSource();

        var verification = fixture.Service.VerifyAsync(Json(envelope), cancellation.Token);
        await replay.Entered;
        cancellation.Cancel();

        Assert.CatchAsync<OperationCanceledException>(async () => await verification);
    }

    [Test]
    public async Task Concurrent_key_revocation_is_detected_by_post_crypto_state_read()
    {
        var provider = new DevelopmentHipCryptoProvider();
        var keyPair = provider.GenerateKeyPair();
        var replacement = provider.GenerateKeyPair();
        var fingerprintService = new HipPublicKeyFingerprintService([provider]);
        var activeRing = SigningKeyRing.Create(IdentityId).RegisterActiveKey(
            InitialKeyId,
            keyPair.Algorithm,
            keyPair.PublicKey,
            fingerprintService.ComputePublicKeyFingerprint(keyPair.Algorithm, keyPair.PublicKey),
            ActivatedAt);
        var revokedRing = activeRing.ReplaceCompromised(
            InitialKeyId,
            "replacement-key",
            replacement.Algorithm,
            replacement.PublicKey,
            fingerprintService.ComputePublicKeyFingerprint(replacement.Algorithm, replacement.PublicKey),
            Now.AddMilliseconds(-1));
        var identity = Identity(keyPair, VerificationStatus.Verified);
        var repository = new TransitioningSigningKeyLifecycleRepository(identity, activeRing, revokedRing);
        var replay = new CountingReplayProtectionService();
        var core = new HipSignedDocumentVerifier(
            repository,
            new HipSignatureProviderFactory([provider]),
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new Rfc8785CanonicalJsonService());
        var service = Service(core, replay);
        var envelope = Sign(CreateEnvelope(provider), provider, keyPair.PrivateKey);

        var result = await service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.KeyRevoked));
            Assert.That(repository.KeyRingReadCount, Is.EqualTo(2));
            Assert.That(replay.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Concurrent_issuer_revocation_is_detected_by_post_crypto_state_read()
    {
        var provider = new DevelopmentHipCryptoProvider();
        var keyPair = provider.GenerateKeyPair();
        var fingerprintService = new HipPublicKeyFingerprintService([provider]);
        var activeRing = SigningKeyRing.Create(IdentityId).RegisterActiveKey(
            InitialKeyId,
            keyPair.Algorithm,
            keyPair.PublicKey,
            fingerprintService.ComputePublicKeyFingerprint(keyPair.Algorithm, keyPair.PublicKey),
            ActivatedAt);
        var repository = new TransitioningIssuerSigningKeyLifecycleRepository(
            Identity(keyPair, VerificationStatus.Verified),
            Identity(keyPair, VerificationStatus.Revoked),
            activeRing);
        var replay = new CountingReplayProtectionService();
        var core = new HipSignedDocumentVerifier(
            repository,
            new HipSignatureProviderFactory([provider]),
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new Rfc8785CanonicalJsonService());
        var service = Service(core, replay);
        var envelope = Sign(CreateEnvelope(provider), provider, keyPair.PrivateKey);

        var result = await service.VerifyAsync(Json(envelope), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(HipEnvelopeVerificationStatus.IssuerRevoked));
            Assert.That(repository.IdentityReadCount, Is.EqualTo(2));
            Assert.That(replay.CallCount, Is.Zero);
        });
    }

    private static async Task<Fixture> CreateFixtureAsync(
        IHipReplayProtectionService? replayProtectionService = null,
        VerificationStatus issuerStatus = VerificationStatus.Verified)
    {
        var provider = new DevelopmentHipCryptoProvider();
        var keyPair = provider.GenerateKeyPair();
        var repository = new InMemorySigningKeyLifecycleRepository();
        var audit = new AuditLogService(repository);
        var lifecycle = new SigningKeyLifecycleService(
            repository,
            audit,
            new HipPublicKeyFingerprintService([provider]));
        await lifecycle.RegisterIdentityAsync(
            new RegisterIdentitySigningKeyRequest(
                Identity(keyPair, issuerStatus),
                InitialKeyId,
                "system:test",
                "Register envelope verification fixture",
                ActivatedAt),
            CancellationToken.None);
        var providerFactory = new RecordingSignatureProviderFactory(
            new HipSignatureProviderFactory([provider]));
        var signedDocumentVerifier = new HipSignedDocumentVerifier(
            repository,
            providerFactory,
            SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm),
            new Rfc8785CanonicalJsonService());
        var replay = replayProtectionService ?? new HipReplayProtectionService(
            new InMemoryReplayMessageIdStore(),
            new InMemoryReplayNonceStore(),
            HipReplayProtectionPolicy.Default,
            new FixedTimeProvider(Now));

        return new Fixture(
            Service(signedDocumentVerifier, replay),
            repository,
            lifecycle,
            provider,
            keyPair,
            providerFactory);
    }

    private static HipEnvelopeVerificationService Service(
        IHipSignedDocumentVerifier signedDocumentVerifier,
        IHipReplayProtectionService replayProtectionService) =>
        new(signedDocumentVerifier, replayProtectionService, new FixedTimeProvider(Now));

    private static HipIdentity Identity(HipKeyPair keyPair, VerificationStatus status) => new(
        IdentityId,
        IdentitySubjectType.Website,
        "Envelope Example",
        keyPair.PublicKey,
        keyPair.Algorithm,
        status,
        ActivatedAt,
        "envelope.example");

    private static HipProtocolEnvelope CreateEnvelope(
        DevelopmentHipCryptoProvider provider,
        string messageId = "msg-envelope-1",
        string nonce = NonceOne,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null) => new(
        HipProtocolVersion.Current,
        messageId,
        nonce,
        new HipProtocolIssuer(IdentityId),
        new HipProtocolSubject(IdentitySubjectType.Website, "envelope.example"),
        new HipContentDigest("sha256", new string('a', 64)),
        Claims("browser-extension"),
        Signature(provider),
        issuedAtUtc ?? Now.AddSeconds(-30),
        expiresAtUtc ?? Now.AddMinutes(1));

    private static HipProtocolClaims Claims(string source) => new(
        new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["source"] = JsonValue($"\"{source}\"")
        });

    private static HipProtocolSignature Signature(
        DevelopmentHipCryptoProvider provider,
        string keyId = InitialKeyId,
        string? algorithm = null,
        SignatureAlgorithmFamily? family = null,
        string value = "unsigned-placeholder") => new(
        HipProtocolSignature.OriginAndIntegrityScope,
        keyId,
        algorithm ?? provider.Capabilities.Algorithm,
        family ?? provider.Capabilities.AlgorithmFamily,
        HipProtocolSignature.Rfc8785Canonicalization,
        value);

    private static HipProtocolEnvelope Sign(
        HipProtocolEnvelope envelope,
        DevelopmentHipCryptoProvider provider,
        string privateKey)
    {
        var canonical = new Rfc8785CanonicalJsonService().Canonicalize(
            HipProtocolEnvelopeSigningPayload.Create(envelope));
        var hash = $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
        return Copy(
            envelope,
            signature: new HipProtocolSignature(
                envelope.Signature.Scope,
                envelope.Signature.KeyId,
                envelope.Signature.Algorithm,
                envelope.Signature.AlgorithmFamily,
                envelope.Signature.Canonicalization,
                provider.SignHash(hash, privateKey)));
    }

    private static HipProtocolEnvelope Copy(
        HipProtocolEnvelope source,
        string? messageId = null,
        string? nonce = null,
        HipProtocolIssuer? issuer = null,
        HipProtocolSubject? subject = null,
        HipContentDigest? contentDigest = null,
        HipProtocolClaims? claims = null,
        HipProtocolSignature? signature = null,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null) => new(
        source.Version,
        messageId ?? source.MessageId,
        nonce ?? source.Nonce,
        issuer ?? source.Issuer,
        subject ?? source.Subject,
        contentDigest ?? source.ContentDigest,
        claims ?? source.Claims,
        signature ?? source.Signature,
        issuedAtUtc ?? source.IssuedAtUtc,
        expiresAtUtc ?? source.ExpiresAtUtc);

    private static byte[] Json(HipProtocolEnvelope envelope) =>
        Encoding.UTF8.GetBytes(HipProtocolEnvelopeJson.Serialize(envelope));

    private static JsonElement JsonValue(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private sealed record Fixture(
        HipEnvelopeVerificationService Service,
        InMemorySigningKeyLifecycleRepository Repository,
        SigningKeyLifecycleService Lifecycle,
        DevelopmentHipCryptoProvider Provider,
        HipKeyPair KeyPair,
        RecordingSignatureProviderFactory ProviderFactory)
    {
        public HipProtocolEnvelope Sign(HipProtocolEnvelope envelope) =>
            HipEnvelopeVerificationServiceTests.Sign(envelope, Provider, KeyPair.PrivateKey);
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class RecordingSignatureProviderFactory(IHipSignatureProviderFactory inner)
        : IHipSignatureProviderFactory
    {
        public List<string> RequestedAlgorithms { get; } = [];

        public IHipSignatureProvider GetRequiredProvider(
            string algorithm,
            SignatureProviderOperations requiredOperations,
            SignatureProviderRuntimePolicy policy)
        {
            RequestedAlgorithms.Add(algorithm);
            return inner.GetRequiredProvider(algorithm, requiredOperations, policy);
        }
    }

    private sealed class ThrowingVerificationSignatureProvider(IHipSignatureProvider inner)
        : IHipSignatureProvider
    {
        public SignatureProviderCapabilities Capabilities => inner.Capabilities;

        public string SignHash(string contentHash, string privateKey) =>
            inner.SignHash(contentHash, privateKey);

        public bool VerifySignature(string contentHash, string signatureValue, string publicKey) =>
            throw new TimeoutException("simulated provider timeout with internal details");
    }

    private sealed class ThrowingCanonicalJsonService : ICanonicalJsonService
    {
        public byte[] Canonicalize(ReadOnlySpan<byte> utf8Json) =>
            throw new IOException("simulated canonicalizer failure with internal details");
    }

    private sealed class CountingReplayProtectionService : IHipReplayProtectionService
    {
        public int CallCount { get; private set; }

        public Task<HipReplayProtectionResult> ValidateAndReserveAsync(
            HipProtocolEnvelope envelope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(new HipReplayProtectionResult(HipReplayProtectionStatus.Accepted));
        }
    }

    private sealed class FixedReplayProtectionService(HipReplayProtectionStatus status)
        : IHipReplayProtectionService
    {
        public Task<HipReplayProtectionResult> ValidateAndReserveAsync(
            HipProtocolEnvelope envelope,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new HipReplayProtectionResult(status));
        }
    }

    private sealed class BlockingReplayProtectionService : IHipReplayProtectionService
    {
        private readonly TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Entered => entered.Task;

        public async Task<HipReplayProtectionResult> ValidateAndReserveAsync(
            HipProtocolEnvelope envelope,
            CancellationToken cancellationToken)
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable after cancellation.");
        }
    }

    private sealed class ThrowingSigningKeyLifecycleRepository : ISigningKeyLifecycleRepository
    {
        public Task<HipIdentity?> GetRegisteredIdentityAsync(string identityId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("simulated repository failure with internal details");

        public Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("simulated repository failure with internal details");

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class TransitioningSigningKeyLifecycleRepository(
        HipIdentity identity,
        SigningKeyRing initialRing,
        SigningKeyRing refreshedRing) : ISigningKeyLifecycleRepository
    {
        public int KeyRingReadCount { get; private set; }

        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<HipIdentity?>(identity);
        }

        public Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            KeyRingReadCount++;
            return Task.FromResult<SigningKeyRing?>(KeyRingReadCount == 1 ? initialRing : refreshedRing);
        }

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class TransitioningIssuerSigningKeyLifecycleRepository(
        HipIdentity initialIdentity,
        HipIdentity refreshedIdentity,
        SigningKeyRing keyRing) : ISigningKeyLifecycleRepository
    {
        public int IdentityReadCount { get; private set; }

        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IdentityReadCount++;
            return Task.FromResult<HipIdentity?>(
                IdentityReadCount == 1 ? initialIdentity : refreshedIdentity);
        }

        public Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<SigningKeyRing?>(keyRing);
        }

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
