using HIP.Application;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json;

namespace HIP.Tests.Protocol;

[NonParallelizable]
public sealed class SigningKeyRingLifecycleTests
{
    private static readonly DateTimeOffset InitialTime =
        new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private const string FirstFingerprint = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private const string SecondFingerprint = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    private const string ThirdFingerprint = "sha256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    [Test]
    public void Domain_states_allow_only_explicit_forward_transitions()
    {
        var active = ManagedSigningKey.CreateActive(
            "key-1", "ML-DSA-65", "public-key", FirstFingerprint, InitialTime);
        var retiring = active.BeginRotation("key-2", InitialTime.AddMinutes(1));
        var retired = retiring.Retire(InitialTime.AddMinutes(2));
        var revoked = retired.Revoke(InitialTime.AddMinutes(3));

        Assert.Multiple(() =>
        {
            Assert.That(active.Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(active.CanCreateSignature, Is.True);
            Assert.That(active.CanVerifyHistoricalSignature, Is.True);
            Assert.That(retiring.Status, Is.EqualTo(SigningKeyStatus.Retiring));
            Assert.That(retiring.CanCreateSignature, Is.False);
            Assert.That(retiring.ReplacementKeyId, Is.EqualTo("key-2"));
            Assert.That(retired.Status, Is.EqualTo(SigningKeyStatus.Retired));
            Assert.That(retired.CanVerifyHistoricalSignature, Is.True);
            Assert.That(revoked.Status, Is.EqualTo(SigningKeyStatus.Revoked));
            Assert.That(revoked.CanVerifyHistoricalSignature, Is.False);
            Assert.That(revoked.Version, Is.EqualTo(4));
        });
    }

    [Test]
    public void Invalid_or_reversed_transitions_fail_closed()
    {
        var active = ManagedSigningKey.CreateActive(
            "key-1", "ML-DSA-65", "public-key", FirstFingerprint, InitialTime);
        var retiring = active.BeginRotation("key-2", InitialTime.AddMinutes(1));
        var retired = retiring.Retire(InitialTime.AddMinutes(2));
        var revoked = retired.Revoke(InitialTime.AddMinutes(3));

        Assert.Multiple(() =>
        {
            Assert.Throws<InvalidOperationException>(() => active.Revoke(InitialTime.AddMinutes(1)));
            Assert.Throws<InvalidOperationException>(() => active.Retire(InitialTime.AddMinutes(1)));
            Assert.Throws<InvalidOperationException>(() => retiring.BeginRotation("key-3", InitialTime.AddMinutes(2)));
            Assert.Throws<InvalidOperationException>(() => retired.BeginRotation("key-3", InitialTime.AddMinutes(3)));
            Assert.Throws<InvalidOperationException>(() => revoked.Retire(InitialTime.AddMinutes(4)));
            Assert.Throws<InvalidOperationException>(() => revoked.Revoke(InitialTime.AddMinutes(4)));
        });
    }

    [Test]
    public void Identifier_limits_match_protocol_and_persistence_contracts()
    {
        var maximumIdentityId = new string('i', SigningKeyLifecycleLimits.MaximumIdentityIdLength);
        var maximumKeyId = new string('k', SigningKeyLifecycleLimits.MaximumKeyIdLength);

        var keyRing = SigningKeyRing.Create(maximumIdentityId)
            .RegisterActiveKey(
                maximumKeyId, "ML-DSA-65", "public-key", FirstFingerprint, InitialTime);

        Assert.Multiple(() =>
        {
            Assert.That(keyRing.IdentityId, Has.Length.EqualTo(220));
            Assert.That(keyRing.Keys.Single().KeyId, Has.Length.EqualTo(128));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                SigningKeyRing.Create(new string('i', SigningKeyLifecycleLimits.MaximumIdentityIdLength + 1)));
            Assert.Throws<ArgumentOutOfRangeException>(() => SigningKeyRing.Create("hip:domain:example")
                .RegisterActiveKey(
                    new string('k', SigningKeyLifecycleLimits.MaximumKeyIdLength + 1),
                    "ML-DSA-65",
                    "public-key",
                    FirstFingerprint,
                    InitialTime));
        });
    }

    [Test]
    public void Historical_verification_uses_the_original_signing_window_and_fails_closed_at_cutoff()
    {
        var active = ManagedSigningKey.CreateActive(
            "key-1", "ML-DSA-65", "public-key", FirstFingerprint, InitialTime);
        var retiring = active.BeginRotation("key-2", InitialTime.AddMinutes(1));
        var retired = retiring.Retire(InitialTime.AddMinutes(2));
        var revoked = retired.Revoke(InitialTime.AddMinutes(3));

        Assert.Multiple(() =>
        {
            Assert.That(retiring.CanVerifySignatureIssuedAt(InitialTime.AddTicks(-1)), Is.False);
            Assert.That(retiring.CanVerifySignatureIssuedAt(InitialTime), Is.True);
            Assert.That(retiring.CanVerifySignatureIssuedAt(InitialTime.AddMinutes(1).AddTicks(-1)), Is.True);
            Assert.That(retiring.CanVerifySignatureIssuedAt(InitialTime.AddMinutes(1)), Is.False);
            Assert.That(retired.CanVerifySignatureIssuedAt(InitialTime.AddSeconds(30)), Is.True);
            Assert.That(retired.CanVerifySignatureIssuedAt(InitialTime.AddMinutes(1)), Is.False);
            Assert.That(revoked.CanVerifySignatureIssuedAt(InitialTime.AddSeconds(30)), Is.False);
        });
    }

    [Test]
    public void Key_identifiers_and_canonical_public_material_cannot_be_reused()
    {
        var initial = SigningKeyRing.Create("hip:domain:example")
            .RegisterActiveKey(
                "key-1", "ML-DSA-65", "public-key-1", FirstFingerprint, InitialTime);
        var rotated = initial.Rotate(
            "key-1", "key-2", "ML-DSA-65", "public-key-2", SecondFingerprint,
            InitialTime.AddMinutes(1));
        var revokedOldKey = rotated.Revoke("key-1", InitialTime.AddMinutes(2));

        Assert.Multiple(() =>
        {
            Assert.Throws<InvalidOperationException>(() => initial.Rotate(
                "key-1", "key-1", "ML-DSA-65", "public-key-3", ThirdFingerprint,
                InitialTime.AddMinutes(1)));
            Assert.Throws<InvalidOperationException>(() => revokedOldKey.Rotate(
                "key-2", "key-3", "ML-DSA-65", "public-key-1", FirstFingerprint,
                InitialTime.AddMinutes(3)));
        });
    }

    [Test]
    public void Canonical_fingerprint_reuse_is_rejected_on_rotation_emergency_and_deserialization()
    {
        const string originalPem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";
        const string rewrappedOriginalPem = "-----BEGIN PUBLIC KEY-----\r\nAA\r\nAA\r\n-----END PUBLIC KEY-----";
        var initial = SigningKeyRing.Create("hip:domain:example")
            .RegisterActiveKey(
                "key-1",
                "ML-DSA-65",
                originalPem,
                FirstFingerprint,
                InitialTime);
        var rotated = initial.Rotate(
            "key-1",
            "key-2",
            "ML-DSA-65",
            "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----",
            SecondFingerprint,
            InitialTime.AddMinutes(1));

        Assert.Multiple(() =>
        {
            Assert.Throws<InvalidOperationException>(() => rotated.Rotate(
                "key-2",
                "key-3",
                "ML-DSA-65",
                rewrappedOriginalPem,
                FirstFingerprint,
                InitialTime.AddMinutes(2)));
            Assert.Throws<InvalidOperationException>(() => rotated.ReplaceCompromised(
                "key-2",
                "key-3",
                "ML-DSA-65",
                rewrappedOriginalPem,
                FirstFingerprint,
                InitialTime.AddMinutes(2)));
            Assert.That(rotated.GetRequiredKey("key-1").PublicKey, Is.EqualTo(originalPem));
        });

        var serialized = JsonSerializer.Serialize(rotated);
        var tampered = serialized.Replace(SecondFingerprint, FirstFingerprint, StringComparison.Ordinal);

        Assert.Throws<ArgumentException>(() => JsonSerializer.Deserialize<SigningKeyRing>(tampered));
    }

    [Test]
    public async Task Rotation_atomically_activates_replacement_and_preserves_historical_metadata()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-key-1",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);

        var rotation = await fixture.Service.RotateAsync(new RotateSigningKeyRequest(
            registered.IdentityId,
            "key-1",
            registered.Version,
            "key-2",
            "ML-DSA-65",
            "public-key-2",
            "operator-1",
            "Scheduled rotation",
            InitialTime.AddDays(30)), CancellationToken.None);

        var stored = await fixture.Repository.GetAsync(registered.IdentityId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(rotation.PreviousKey.Status, Is.EqualTo(SigningKeyStatus.Retiring));
            Assert.That(rotation.PreviousKey.ReplacementKeyId, Is.EqualTo("key-2"));
            Assert.That(rotation.ReplacementKey.Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(rotation.KeyRing.Version, Is.EqualTo(2));
            Assert.That(stored, Is.EqualTo(rotation.KeyRing));
            Assert.That(rotation.PreviousKey.CanVerifyHistoricalSignature, Is.True);
        });
    }

    [Test]
    public async Task Emergency_replacement_atomically_revokes_compromised_active_key_and_activates_unique_replacement()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-sensitive-material",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);

        var replacement = await fixture.Service.EmergencyReplaceAsync(new EmergencyReplaceSigningKeyRequest(
            registered.IdentityId,
            "key-1",
            registered.Version,
            "key-2",
            "ML-DSA-65",
            "replacement-public-material",
            "security-operator",
            "Confirmed signing-key compromise",
            InitialTime.AddMinutes(1)), CancellationToken.None);

        var stored = await fixture.Repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var audits = await fixture.Audit.ListAsync(CancellationToken.None);
        var auditText = string.Join('|', audits.Select(entry =>
            $"{entry.ActorId}:{entry.Action}:{entry.Summary}:{string.Join(',', entry.Metadata.Select(pair => $"{pair.Key}={pair.Value}"))}"));

        Assert.Multiple(() =>
        {
            Assert.That(replacement.CompromisedKey.Status, Is.EqualTo(SigningKeyStatus.Revoked));
            Assert.That(replacement.CompromisedKey.ReplacementKeyId, Is.EqualTo("key-2"));
            Assert.That(replacement.ReplacementKey.Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(replacement.KeyRing.Keys.Count(key => key.Status == SigningKeyStatus.Active), Is.EqualTo(1));
            Assert.That(replacement.KeyRing.Version, Is.EqualTo(registered.Version + 1));
            Assert.That(stored, Is.EqualTo(replacement.KeyRing));
            Assert.That(audits.Count, Is.EqualTo(3));
            Assert.That(auditText, Does.Contain("SigningKeyEmergencyRevoked"));
            Assert.That(auditText, Does.Contain("SigningKeyEmergencyReplacementActivated"));
            Assert.That(auditText, Does.Contain("Confirmed signing-key compromise"));
            Assert.That(auditText, Does.Not.Contain("public-sensitive-material"));
            Assert.That(auditText, Does.Not.Contain("replacement-public-material"));
        });
    }

    [Test]
    public async Task Direct_revocation_of_active_key_is_rejected_without_state_or_audit_change()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-key",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);
        var auditCount = (await fixture.Audit.ListAsync(CancellationToken.None)).Count;

        Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Service.RevokeAsync(
            new ChangeSigningKeyStateRequest(
                registered.IdentityId,
                "key-1",
                registered.Version,
                "security-operator",
                "Compromised",
                InitialTime.AddMinutes(1)),
            CancellationToken.None));

        var stored = await fixture.Repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var finalAuditCount = (await fixture.Audit.ListAsync(CancellationToken.None)).Count;

        Assert.Multiple(() =>
        {
            Assert.That(stored, Is.EqualTo(registered));
            Assert.That(stored!.Keys.Single().Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(finalAuditCount, Is.EqualTo(auditCount));
        });
    }

    [Test]
    public async Task Signing_and_historical_verification_resolution_enforce_lifecycle_policy()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-key-1",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);
        var rotation = await fixture.Service.RotateAsync(new RotateSigningKeyRequest(
            registered.IdentityId, "key-1", registered.Version, "key-2", "ML-DSA-65", "public-key-2",
            "operator-1", "Scheduled rotation", InitialTime.AddMinutes(1)), CancellationToken.None);

        var activeForSigning = await fixture.Service.GetRequiredSigningKeyAsync(
            registered.IdentityId, "key-2", CancellationToken.None);
        var oldForVerification = await fixture.Service.GetRequiredHistoricalVerificationKeyAsync(
            registered.IdentityId, "key-1", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(activeForSigning.KeyId, Is.EqualTo("key-2"));
            Assert.That(oldForVerification.KeyId, Is.EqualTo("key-1"));
            Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Service.GetRequiredSigningKeyAsync(
                registered.IdentityId, "key-1", CancellationToken.None));
        });

        var revokedRing = await fixture.Service.RevokeAsync(new ChangeSigningKeyStateRequest(
            registered.IdentityId, "key-1", rotation.KeyRing.Version,
            "security-operator", "Historical key compromised", InitialTime.AddMinutes(2)), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(revokedRing.GetRequiredKey("key-1").Status, Is.EqualTo(SigningKeyStatus.Revoked));
            Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Service.GetRequiredHistoricalVerificationKeyAsync(
                registered.IdentityId, "key-1", CancellationToken.None));
        });
    }

    [Test]
    public async Task Retire_and_revoke_write_privacy_safe_audit_evidence()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-sensitive-material",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);
        var rotation = await fixture.Service.RotateAsync(new RotateSigningKeyRequest(
            registered.IdentityId, "key-1", registered.Version, "key-2", "ML-DSA-65", "replacement-public-material",
            "operator-1", "Scheduled rotation", InitialTime.AddMinutes(1)), CancellationToken.None);

        var retiredRing = await fixture.Service.RetireAsync(new ChangeSigningKeyStateRequest(
            registered.IdentityId, "key-1", rotation.KeyRing.Version,
            "operator-2", "Rotation overlap complete", InitialTime.AddMinutes(2)), CancellationToken.None);
        var emergencyReplacement = await fixture.Service.EmergencyReplaceAsync(
            new EmergencyReplaceSigningKeyRequest(
                registered.IdentityId, "key-2", retiredRing.Version,
                "key-3", "ML-DSA-65", "emergency-public-material",
                "security-operator", "Key compromise response", InitialTime.AddMinutes(3)),
            CancellationToken.None);
        var audits = await fixture.Audit.ListAsync(CancellationToken.None);
        var auditText = string.Join('|', audits.Select(entry =>
            $"{entry.ActorId}:{entry.Action}:{entry.Summary}:{string.Join(',', entry.Metadata.Select(pair => $"{pair.Key}={pair.Value}"))}"));

        Assert.Multiple(() =>
        {
            Assert.That(retiredRing.GetRequiredKey("key-1").CanVerifyHistoricalSignature, Is.True);
            Assert.That(emergencyReplacement.CompromisedKey.CanVerifyHistoricalSignature, Is.False);
            Assert.That(emergencyReplacement.ReplacementKey.CanCreateSignature, Is.True);
            Assert.That(audits.Count, Is.EqualTo(6));
            Assert.That(auditText, Does.Contain("operator-2"));
            Assert.That(auditText, Does.Contain("Rotation overlap complete"));
            Assert.That(auditText, Does.Contain("2026-07-17T12:02:00.0000000+00:00"));
            Assert.That(auditText, Does.Not.Contain("public-sensitive-material"));
            Assert.That(auditText, Does.Not.Contain("replacement-public-material"));
            Assert.That(auditText, Does.Not.Contain("emergency-public-material"));
        });
    }

    [Test]
    public async Task Stale_aggregate_version_is_rejected_without_state_or_audit_change()
    {
        var fixture = CreateFixture();
        var registered = await fixture.Service.RegisterAsync(new RegisterSigningKeyRequest(
            "hip:domain:example", "key-1", "ML-DSA-65", "public-key",
            "operator-1", "Initial key", InitialTime), CancellationToken.None);
        var replacement = await fixture.Service.EmergencyReplaceAsync(new EmergencyReplaceSigningKeyRequest(
            registered.IdentityId, "key-1", registered.Version,
            "key-2", "ML-DSA-65", "replacement-public-key",
            "operator-1", "Compromised", InitialTime.AddMinutes(1)), CancellationToken.None);
        var auditCount = (await fixture.Audit.ListAsync(CancellationToken.None)).Count;

        var exception = Assert.ThrowsAsync<SigningKeyConcurrencyException>(() =>
            fixture.Service.EmergencyReplaceAsync(new EmergencyReplaceSigningKeyRequest(
                registered.IdentityId, "key-1", registered.Version,
                "key-3", "ML-DSA-65", "third-public-key",
                "operator-2", "Stale request", InitialTime.AddMinutes(2)), CancellationToken.None));
        var stored = await fixture.Repository.GetAsync(registered.IdentityId, CancellationToken.None);
        var finalAuditCount = (await fixture.Audit.ListAsync(CancellationToken.None)).Count;

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Contain("stale"));
            Assert.That(stored, Is.EqualTo(replacement.KeyRing));
            Assert.That(finalAuditCount, Is.EqualTo(auditCount));
        });
    }

    [Test]
    public void Lifecycle_metadata_contains_no_private_key_surface()
    {
        var propertyNames = typeof(ManagedSigningKey).GetProperties().Select(property => property.Name);

        Assert.That(propertyNames, Does.Not.Contain("PrivateKey"));
    }

    [Test]
    public void Application_registration_exposes_lifecycle_service_and_repository()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISigningKeyLifecycleRepository, InMemorySigningKeyLifecycleRepository>();
        services.AddSingleton<IAuditLogRepository, InMemoryAuditLogRepository>();
        services.AddHipApplication();
        using var provider = services.BuildServiceProvider();

        Assert.Multiple(() =>
        {
            Assert.That(provider.GetRequiredService<ISigningKeyLifecycleService>(), Is.TypeOf<SigningKeyLifecycleService>());
            Assert.That(
                provider.GetRequiredService<ISigningKeyLifecycleRepository>(),
                Is.TypeOf<InMemorySigningKeyLifecycleRepository>());
        });
    }

    private static LifecycleFixture CreateFixture()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var audit = new AuditLogService(repository);
        return new LifecycleFixture(
            repository,
            audit,
            new SigningKeyLifecycleService(repository, audit, new DeterministicFingerprintService()));
    }

    private sealed class DeterministicFingerprintService : IHipPublicKeyFingerprintService
    {
        public string ComputePublicKeyFingerprint(string algorithm, string publicKey)
        {
            var input = System.Text.Encoding.UTF8.GetBytes($"{algorithm.Length}:{algorithm}{publicKey}");
            var digest = System.Security.Cryptography.SHA256.HashData(input);
            return $"sha256:{Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
        }
    }

    private sealed record LifecycleFixture(
        InMemorySigningKeyLifecycleRepository Repository,
        AuditLogService Audit,
        SigningKeyLifecycleService Service);
}
