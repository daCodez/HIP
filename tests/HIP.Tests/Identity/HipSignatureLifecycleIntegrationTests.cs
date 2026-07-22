using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;

namespace HIP.Tests.Identity;

/// <summary>
/// Proves that the legacy signature facade cannot bypass managed signing-key lifecycle policy.
/// </summary>
public sealed class HipSignatureLifecycleIntegrationTests
{
    private static readonly DateTimeOffset InitialActivation =
        new(2026, 7, 18, 10, 0, 0, TimeSpan.Zero);

    [Test]
    public void Public_verification_requests_do_not_expose_a_caller_controlled_signing_time()
    {
        Assert.Multiple(() =>
        {
            Assert.That(typeof(VerifySignatureRequest).GetProperty("TrustedSignedAtUtc"), Is.Null);
            Assert.That(typeof(HipSignatureVerificationRequest).GetProperty("TrustedSignedAtUtc"), Is.Null);
        });
    }

    [Test]
    public async Task SignAsync_returns_the_authorized_managed_key_identifier()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(keyPair, "hip:app:managed-signing");
        var lifecycle = CreateLifecycle();
        await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-1", keyPair);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);
        var contentHash = crypto.HashContent("managed payload");

        var signature = await service.SignAsync(
            new HipSignatureRequest(
                identity.IdentityId,
                contentHash,
                keyPair.PrivateKey,
                ExpiresAtUtc: null,
                KeyId: "key-1"),
            CancellationToken.None);

        Assert.That(signature.KeyId, Is.EqualTo("key-1"));
        Assert.That(signature.Algorithm, Is.EqualTo(keyPair.Algorithm));
    }

    [Test]
    public async Task Identity_registration_bootstraps_the_default_key_for_development_signing()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var repository = new InMemorySigningKeyLifecycleRepository();
        var lifecycle = new SigningKeyLifecycleService(
            repository,
            new AuditLogService(repository),
            DevelopmentFingerprintService());
        var identityService = new HipIdentityService(crypto, repository, lifecycle);
        var registered = await identityService.RegisterAsync(
            new IdentityRegistrationRequest(IdentitySubjectType.App, "Managed App", "managed-app"),
            CancellationToken.None);

        var signature = await identityService.SignAsync(
            new SignContentRequest(
                registered.Identity.IdentityId,
                crypto.HashContent("registration-to-signing"),
                registered.DevelopmentPrivateKey!,
                ExpiresAtUtc: null),
            CancellationToken.None);
        var managedKey = await lifecycle.GetRequiredSigningKeyAsync(
            registered.Identity.IdentityId,
            HipIdentityService.InitialSigningKeyId,
            CancellationToken.None);

        Assert.That(signature.KeyId, Is.EqualTo(HipIdentityService.InitialSigningKeyId));
        Assert.That(managedKey.PublicKey, Is.EqualTo(registered.Identity.PublicKey));
    }

    [Test]
    public async Task Legacy_identity_signing_bootstraps_missing_lifecycle_once()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(keyPair, "hip:app:legacy-read-through");
        var lifecycleRepository = new InMemorySigningKeyLifecycleRepository();
        var lifecycle = new SigningKeyLifecycleService(
            lifecycleRepository,
            new AuditLogService(lifecycleRepository),
            new HipPublicKeyFingerprintService([crypto]));
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);
        var contentHash = crypto.HashContent("legacy lifecycle bootstrap");

        var first = await service.SignAsync(
            new HipSignatureRequest(
                identity.IdentityId,
                contentHash,
                keyPair.PrivateKey,
                ExpiresAtUtc: null,
                KeyId: HipIdentityService.InitialSigningKeyId),
            CancellationToken.None);
        var second = await service.SignAsync(
            new HipSignatureRequest(
                identity.IdentityId,
                contentHash,
                keyPair.PrivateKey,
                ExpiresAtUtc: null,
                KeyId: HipIdentityService.InitialSigningKeyId),
            CancellationToken.None);

        var ring = await lifecycleRepository.GetAsync(identity.IdentityId, CancellationToken.None);
        var audits = await lifecycleRepository.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.KeyId, Is.EqualTo(HipIdentityService.InitialSigningKeyId));
            Assert.That(second.KeyId, Is.EqualTo(HipIdentityService.InitialSigningKeyId));
            Assert.That(ring, Is.Not.Null);
            Assert.That(ring!.Version, Is.EqualTo(1));
            Assert.That(ring.Keys, Has.Count.EqualTo(1));
            Assert.That(ring.Keys.Single().PublicKey, Is.EqualTo(identity.PublicKey));
            Assert.That(audits, Has.Count.EqualTo(1));
        });
    }

    [Test]
    public async Task Public_verification_cannot_preclaim_a_legacy_identity_key_identifier()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(
            keyPair,
            $"hip:app:legacy-verify-preclaim-{Guid.NewGuid():N}");
        var lifecycleRepository = new InMemorySigningKeyLifecycleRepository();
        var lifecycle = new SigningKeyLifecycleService(
            lifecycleRepository,
            new AuditLogService(lifecycleRepository),
            new HipPublicKeyFingerprintService([crypto]));
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var result = await service.VerifyAsync(
            new HipSignatureVerificationRequest(
                identity.IdentityId,
                crypto.HashContent("untrusted verification request"),
                "attacker-supplied-signature",
                "Unknown",
                KeyId: "attacker-selected-key"),
            CancellationToken.None);

        var ring = await lifecycleRepository.GetAsync(identity.IdentityId, CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(ring, Is.Not.Null);
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Reason, Does.Contain("not found"));
            Assert.That(ring!.Keys.Select(key => key.KeyId),
                Is.EqualTo(new[] { HipIdentityService.InitialSigningKeyId }));
            Assert.That(ring.Keys, Has.None.Matches<ManagedSigningKey>(key =>
                key.KeyId == "attacker-selected-key"));
        });
    }

    [Test]
    public async Task Identity_registration_uses_only_the_atomic_commit_when_registration_fails()
    {
        var repository = new ThrowingAtomicRegistrationRepository();
        var lifecycle = new SigningKeyLifecycleService(
            repository,
            new AuditLogService(new InMemoryAuditLogRepository()),
            DevelopmentFingerprintService());
        var identityService = new HipIdentityService(
            new DevelopmentHipCryptoProvider(),
            repository,
            lifecycle);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await identityService.RegisterAsync(
                new IdentityRegistrationRequest(IdentitySubjectType.App, "Rollback App", "rollback-app"),
                CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Contain("atomic registration failed").IgnoreCase);
            Assert.That(repository.AtomicRegistrationWasAttempted, Is.True);
            Assert.That(repository.DirectIdentitySaveWasCalled, Is.False);
        });
    }

    [Test]
    public async Task SignAsync_rejects_private_key_material_that_does_not_match_the_managed_key()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var managedKeyPair = crypto.GenerateKeyPair();
        var wrongKeyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(managedKeyPair, "hip:app:wrong-private-key");
        var lifecycle = CreateLifecycle();
        await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-1", managedKeyPair);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var exception = Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.SignAsync(
                new HipSignatureRequest(
                    identity.IdentityId,
                    crypto.HashContent("mislabeled signature"),
                    wrongKeyPair.PrivateKey,
                    ExpiresAtUtc: null,
                    KeyId: "key-1"),
                CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("does not match"));
    }

    [Test]
    public async Task SignAsync_rejects_a_key_after_rotation_begins()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var oldKeyPair = crypto.GenerateKeyPair();
        var replacementKeyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(oldKeyPair, "hip:app:rotating-signing");
        var lifecycle = CreateLifecycle();
        var initialRing = await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-old", oldKeyPair);
        await lifecycle.RotateAsync(
            new RotateSigningKeyRequest(
                identity.IdentityId,
                "key-old",
                initialRing.Version,
                "key-new",
                replacementKeyPair.Algorithm,
                replacementKeyPair.PublicKey,
                "operator-1",
                "Scheduled signing-key rotation",
                InitialActivation.AddHours(1)),
            CancellationToken.None);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.SignAsync(
                new HipSignatureRequest(
                    identity.IdentityId,
                    crypto.HashContent("must not be signed by old key"),
                    oldKeyPair.PrivateKey,
                    ExpiresAtUtc: null,
                    KeyId: "key-old"),
                CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("not active"));
    }

    [Test]
    public async Task GetPublicKeyAsync_returns_the_active_replacement_after_rotation()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var oldKeyPair = crypto.GenerateKeyPair();
        var replacementKeyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(oldKeyPair, "hip:app:rotated-public-key");
        var lifecycle = CreateLifecycle();
        var initialRing = await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-old", oldKeyPair);
        await lifecycle.RotateAsync(
            new RotateSigningKeyRequest(
                identity.IdentityId,
                "key-old",
                initialRing.Version,
                "key-new",
                replacementKeyPair.Algorithm,
                replacementKeyPair.PublicKey,
                "operator-1",
                "Rotate the public discovery key",
                InitialActivation.AddHours(1)),
            CancellationToken.None);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var publicKey = await service.GetPublicKeyAsync(identity.IdentityId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(publicKey.KeyId, Is.EqualTo("key-new"));
            Assert.That(publicKey.Algorithm, Is.EqualTo(replacementKeyPair.Algorithm));
            Assert.That(publicKey.PublicKey, Is.EqualTo(replacementKeyPair.PublicKey));
        });
    }

    [Test]
    public async Task HipSignatureService_rejects_a_retiring_key_without_trusted_envelope_evidence()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var oldKeyPair = crypto.GenerateKeyPair();
        var replacementKeyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(replacementKeyPair, "hip:web:historical-key");
        var lifecycle = CreateLifecycle();
        var initialRing = await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-old", oldKeyPair);
        var rotationAt = InitialActivation.AddHours(1);
        await lifecycle.RotateAsync(
            new RotateSigningKeyRequest(
                identity.IdentityId,
                "key-old",
                initialRing.Version,
                "key-new",
                replacementKeyPair.Algorithm,
                replacementKeyPair.PublicKey,
                "operator-1",
                "Scheduled signing-key rotation",
                rotationAt),
            CancellationToken.None);
        var contentHash = crypto.HashContent("historical payload");
        var signatureValue = crypto.SignHash(contentHash, oldKeyPair.PrivateKey);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var result = await service.VerifyAsync(
            new HipSignatureVerificationRequest(
                identity.IdentityId,
                contentHash,
                signatureValue,
                "Trusted",
                KeyId: "key-old"),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("cryptographically trusted envelope evidence"));
    }

    [Test]
    public async Task HipIdentityService_rejects_a_retiring_key_without_trusted_envelope_evidence()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var oldKeyPair = crypto.GenerateKeyPair();
        var replacementKeyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(oldKeyPair, "hip:app:identity-retiring-verification");
        var lifecycle = CreateLifecycle();
        var initialRing = await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-old", oldKeyPair);
        await lifecycle.RotateAsync(
            new RotateSigningKeyRequest(
                identity.IdentityId,
                "key-old",
                initialRing.Version,
                "key-new",
                replacementKeyPair.Algorithm,
                replacementKeyPair.PublicKey,
                "operator-1",
                "Scheduled signing-key rotation",
                InitialActivation.AddHours(1)),
            CancellationToken.None);
        var contentHash = crypto.HashContent("identity historical payload");
        var signatureValue = crypto.SignHash(contentHash, oldKeyPair.PrivateKey);
        var service = new HipIdentityService(crypto, IdentityRepository, lifecycle);

        var result = await service.VerifyAsync(
            new VerifySignatureRequest(
                identity.IdentityId,
                contentHash,
                signatureValue,
                KeyId: "key-old"),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("cryptographically trusted envelope evidence"));
    }

    [Test]
    public async Task VerifyAsync_rejects_a_retired_key_without_trusted_envelope_evidence()
    {
        var fixture = await RotatedKeyFixture.CreateAsync(retireOldKey: true);
        var contentHash = fixture.Crypto.HashContent("undated historical payload");
        var signatureValue = fixture.Crypto.SignHash(contentHash, fixture.OldKeyPair.PrivateKey);

        var result = await fixture.Service.VerifyAsync(
            new HipSignatureVerificationRequest(
                fixture.Identity.IdentityId,
                contentHash,
                signatureValue,
                "Trusted",
                KeyId: "key-old"),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("cryptographically trusted envelope evidence"));
    }

    [Test]
    public async Task VerifyAsync_rejects_a_revoked_key_even_for_a_pre_rotation_signature()
    {
        var fixture = await RotatedKeyFixture.CreateAsync(revokeOldKey: true);
        var contentHash = fixture.Crypto.HashContent("revoked historical payload");
        var signatureValue = fixture.Crypto.SignHash(contentHash, fixture.OldKeyPair.PrivateKey);

        var result = await fixture.Service.VerifyAsync(
            new HipSignatureVerificationRequest(
                fixture.Identity.IdentityId,
                contentHash,
                signatureValue,
                "Trusted",
                KeyId: "key-old"),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("revoked"));
    }

    [Test]
    public async Task VerifyAsync_rejects_legacy_requests_without_a_key_identifier()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = await SaveIdentityAsync(keyPair, "hip:app:keyless-legacy");
        var lifecycle = CreateLifecycle();
        await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-1", keyPair);
        var service = new HipSignatureService(crypto, IdentityRepository, lifecycle);

        var exception = Assert.ThrowsAsync<ArgumentException>(async () =>
            await service.VerifyAsync(
                new HipSignatureVerificationRequest(
                    identity.IdentityId,
                    crypto.HashContent("legacy payload"),
                    "legacy-signature",
                    "Unknown"),
                CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("key identifier"));
        Assert.That(exception.Message, Does.Contain("legacy").IgnoreCase);
    }

    private static InMemoryHipIdentityRepository IdentityRepository { get; } = new();

    private static SigningKeyLifecycleService CreateLifecycle() =>
        new(
            new InMemorySigningKeyLifecycleRepository(),
            new AuditLogService(new InMemoryAuditLogRepository()),
            DevelopmentFingerprintService());

    private static IHipPublicKeyFingerprintService DevelopmentFingerprintService() =>
        new HipPublicKeyFingerprintService([new DevelopmentHipCryptoProvider()]);

    private static async Task<HipIdentity> SaveIdentityAsync(HipKeyPair keyPair, string identityId)
    {
        var identity = new HipIdentity(
            identityId,
            IdentitySubjectType.App,
            identityId,
            keyPair.PublicKey,
            keyPair.Algorithm,
            VerificationStatus.Verified,
            InitialActivation,
            identityId);
        await IdentityRepository.SaveAsync(identity, CancellationToken.None);
        return identity;
    }

    private static async Task<SigningKeyRing> RegisterKeyAsync(
        ISigningKeyLifecycleService lifecycle,
        string identityId,
        string keyId,
        HipKeyPair keyPair) =>
        await lifecycle.RegisterAsync(
            new RegisterSigningKeyRequest(
                identityId,
                keyId,
                keyPair.Algorithm,
                keyPair.PublicKey,
                "operator-1",
                "Register managed signing key",
                InitialActivation),
            CancellationToken.None);

    private sealed record RotatedKeyFixture(
        DevelopmentHipCryptoProvider Crypto,
        HipKeyPair OldKeyPair,
        HipIdentity Identity,
        DateTimeOffset RotationAt,
        HipSignatureService Service)
    {
        public static async Task<RotatedKeyFixture> CreateAsync(
            bool retireOldKey = false,
            bool revokeOldKey = false)
        {
            var crypto = new DevelopmentHipCryptoProvider();
            var oldKeyPair = crypto.GenerateKeyPair();
            var replacementKeyPair = crypto.GenerateKeyPair();
            var identity = await SaveIdentityAsync(replacementKeyPair, $"hip:app:fixture-{Guid.NewGuid():N}");
            var lifecycle = CreateLifecycle();
            var initialRing = await RegisterKeyAsync(lifecycle, identity.IdentityId, "key-old", oldKeyPair);
            var rotationAt = InitialActivation.AddHours(1);
            var rotated = await lifecycle.RotateAsync(
                new RotateSigningKeyRequest(
                    identity.IdentityId,
                    "key-old",
                    initialRing.Version,
                    "key-new",
                    replacementKeyPair.Algorithm,
                    replacementKeyPair.PublicKey,
                    "operator-1",
                    "Scheduled signing-key rotation",
                    rotationAt),
                CancellationToken.None);

            if (retireOldKey)
            {
                await lifecycle.RetireAsync(
                    new ChangeSigningKeyStateRequest(
                        identity.IdentityId,
                        "key-old",
                        rotated.KeyRing.Version,
                        "operator-1",
                        "Rotation overlap completed",
                        rotationAt.AddHours(1)),
                    CancellationToken.None);
            }
            else if (revokeOldKey)
            {
                await lifecycle.RevokeAsync(
                    new ChangeSigningKeyStateRequest(
                        identity.IdentityId,
                        "key-old",
                        rotated.KeyRing.Version,
                        "operator-1",
                        "Key compromise confirmed",
                        rotationAt.AddHours(1)),
                    CancellationToken.None);
            }

            return new RotatedKeyFixture(
                crypto,
                oldKeyPair,
                identity,
                rotationAt,
                new HipSignatureService(crypto, IdentityRepository, lifecycle));
        }
    }

    private sealed class ThrowingAtomicRegistrationRepository :
        ISigningKeyLifecycleRepository,
        IHipIdentityRepository
    {
        public bool AtomicRegistrationWasAttempted { get; private set; }

        public bool DirectIdentitySaveWasCalled { get; private set; }

        public Task<HipIdentity?> GetRegisteredIdentityAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            Task.FromResult<HipIdentity?>(null);

        Task<HipIdentity?> IHipIdentityRepository.GetAsync(
            string identityId,
            CancellationToken cancellationToken) =>
            Task.FromResult<HipIdentity?>(null);

        public Task<HipIdentity> SaveAsync(HipIdentity identity, CancellationToken cancellationToken)
        {
            DirectIdentitySaveWasCalled = true;
            return Task.FromResult(identity);
        }

        public Task<bool> TryUpdateAsync(
            HipIdentity expected,
            HipIdentity updated,
            CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<SigningKeyRing?> GetAsync(string identityId, CancellationToken cancellationToken) =>
            Task.FromResult<SigningKeyRing?>(null);

        public Task<bool> TryRegisterIdentityAsync(
            IdentitySigningKeyRegistrationBatch registrationBatch,
            CancellationToken cancellationToken)
        {
            AtomicRegistrationWasAttempted = true;
            throw new InvalidOperationException("Atomic registration failed before commit.");
        }

        public Task<bool> TrySaveAsync(
            SigningKeyLifecycleTransitionBatch transitionBatch,
            CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }
}
