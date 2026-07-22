using HIP.Application.Identity;
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
        var identityRepository = new InMemoryHipIdentityRepository();
        var lifecycle = CreateLifecycle();
        var identityService = new HipIdentityService(crypto, identityRepository, lifecycle);
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
    public async Task VerifyAsync_resolves_the_historical_key_by_identity_and_key_identifier()
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
                KeyId: "key-old",
                TrustedSignedAtUtc: InitialActivation.AddMinutes(30)),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Reason, Does.Contain("key-old"));
    }

    [Test]
    public async Task VerifyAsync_rejects_a_historical_signature_at_the_rotation_cutoff()
    {
        var fixture = await RotatedKeyFixture.CreateAsync();
        var contentHash = fixture.Crypto.HashContent("late payload");
        var signatureValue = fixture.Crypto.SignHash(contentHash, fixture.OldKeyPair.PrivateKey);

        var result = await fixture.Service.VerifyAsync(
            new HipSignatureVerificationRequest(
                fixture.Identity.IdentityId,
                contentHash,
                signatureValue,
                "Trusted",
                KeyId: "key-old",
                TrustedSignedAtUtc: fixture.RotationAt),
            CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("signing window"));
    }

    [Test]
    public async Task VerifyAsync_rejects_a_retired_key_without_a_trusted_signing_time()
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
        Assert.That(result.Reason, Does.Contain("trusted signing time"));
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
                KeyId: "key-old",
                TrustedSignedAtUtc: InitialActivation.AddMinutes(30)),
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
            new AuditLogService(new InMemoryAuditLogRepository()));

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
}
