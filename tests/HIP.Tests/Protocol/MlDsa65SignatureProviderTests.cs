using HIP.Application;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

[NonParallelizable]
public sealed class MlDsa65SignatureProviderTests
{
    [Test]
    public void Capabilities_report_fips_204_algorithm_family_and_runtime_availability()
    {
        var provider = new MlDsa65SignatureProvider();

        Assert.Multiple(() =>
        {
            Assert.That(provider.Capabilities.Algorithm, Is.EqualTo("ML-DSA-65"));
            Assert.That(provider.Capabilities.AlgorithmFamily, Is.EqualTo(SignatureAlgorithmFamily.PostQuantum));
            Assert.That(
                provider.Capabilities.SupportedOperations,
                Is.EqualTo(SignatureProviderOperations.Sign | SignatureProviderOperations.Verify));
            Assert.That(provider.Capabilities.IsAvailable, Is.EqualTo(MlDsa65SignatureProvider.IsRuntimeSupported));
            Assert.That(provider.Capabilities.IsDevelopmentOnly, Is.False);
            Assert.That(provider.Capabilities.EstablishesSafetyOrReputation, Is.False);
        });
    }

    [Test]
    public void Runtime_support_controls_key_generation_signing_and_verification_without_fallback()
    {
        var provider = new MlDsa65SignatureProvider();
        const string contentHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        if (!MlDsa65SignatureProvider.IsRuntimeSupported)
        {
            Assert.Throws<PlatformNotSupportedException>(() => provider.GenerateKeyPair());
            Assert.Throws<PlatformNotSupportedException>(() => provider.SignHash(contentHash, "not-a-key"));
            Assert.Throws<PlatformNotSupportedException>(() => provider.VerifySignature(contentHash, "AA", "not-a-key"));
            return;
        }

        var keyPair = provider.GenerateKeyPair();
        var signature = provider.SignHash(contentHash, keyPair.PrivateKey);

        Assert.Multiple(() =>
        {
            Assert.That(keyPair.Algorithm, Is.EqualTo(MlDsa65SignatureProvider.Algorithm));
            Assert.That(keyPair.IsProductionSafe, Is.True);
            Assert.That(keyPair.PrivateKey, Does.Contain("BEGIN PRIVATE KEY"));
            Assert.That(keyPair.PublicKey, Does.Contain("BEGIN PUBLIC KEY"));
            Assert.That(provider.VerifySignature(contentHash, signature, keyPair.PublicKey), Is.True);
            Assert.That(provider.VerifySignature(contentHash + "00", signature, keyPair.PublicKey), Is.False);
        });
    }

    [Test]
    public void Public_key_fingerprint_is_stable_across_equivalent_pem_line_wrapping()
    {
        var provider = new MlDsa65SignatureProvider();
        if (!MlDsa65SignatureProvider.IsRuntimeSupported)
        {
            Assert.That(provider.Capabilities.IsAvailable, Is.False);
            return;
        }

        var keyPair = provider.GenerateKeyPair();
        var rewrappedPem = RewrapPublicKeyPem(keyPair.PublicKey, lineLength: 37);

        var exportedFingerprint = provider.ComputePublicKeyFingerprint(keyPair.PublicKey);
        var rewrappedFingerprint = provider.ComputePublicKeyFingerprint(rewrappedPem);

        Assert.Multiple(() =>
        {
            Assert.That(rewrappedPem, Is.Not.EqualTo(keyPair.PublicKey));
            Assert.That(rewrappedFingerprint, Is.EqualTo(exportedFingerprint));
            Assert.That(exportedFingerprint, Does.Match("^sha256:[A-Za-z0-9_-]{43}$"));
            Assert.Throws<ArgumentException>(() =>
                provider.ComputePublicKeyFingerprint(keyPair.PrivateKey));
        });
    }

    [Test]
    public void Development_public_key_fingerprint_is_deterministic_and_rejects_non_public_material()
    {
        var provider = new HIP.Application.Identity.DevelopmentHipCryptoProvider();
        var keyPair = provider.GenerateKeyPair();

        var fingerprint = provider.ComputePublicKeyFingerprint(keyPair.PublicKey);

        Assert.Multiple(() =>
        {
            Assert.That(provider.ComputePublicKeyFingerprint(keyPair.PublicKey), Is.EqualTo(fingerprint));
            Assert.That(fingerprint, Does.Match("^sha256:[A-Za-z0-9_-]{43}$"));
            Assert.Throws<ArgumentException>(() =>
                provider.ComputePublicKeyFingerprint(keyPair.PrivateKey));
            Assert.Throws<ArgumentException>(() =>
                provider.ComputePublicKeyFingerprint($" {keyPair.PublicKey}"));
        });
    }

    [Test]
    public void Malformed_or_oversized_inputs_fail_before_cryptographic_processing()
    {
        var provider = new MlDsa65SignatureProvider();
        var oversizedHash = new string('a', MlDsa65SignatureProvider.MaximumContentHashBytes + 1);
        var oversizedKey = new string('k', MlDsa65SignatureProvider.MaximumPemCharacters + 1);

        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentException>(() => provider.SignHash(string.Empty, "key"));
            Assert.Throws<ArgumentException>(() => provider.SignHash(oversizedHash, "key"));
            Assert.Throws<ArgumentException>(() => provider.SignHash("sha256:abc", oversizedKey));
            Assert.Throws<FormatException>(() => provider.VerifySignature("sha256:abc", "%%%", "key"));
            Assert.Throws<FormatException>(() => provider.VerifySignature("sha256:abc", "AA==", "key"));
        });
    }

    [Test]
    public void Production_factory_selects_mldsa65_only_when_runtime_supports_it()
    {
        var provider = new MlDsa65SignatureProvider();
        var factory = new HipSignatureProviderFactory([provider]);
        var policy = SignatureProviderRuntimePolicy.ForProduction(MlDsa65SignatureProvider.Algorithm);

        if (MlDsa65SignatureProvider.IsRuntimeSupported)
        {
            Assert.That(
                factory.GetRequiredProvider(
                    MlDsa65SignatureProvider.Algorithm,
                    SignatureProviderOperations.Sign | SignatureProviderOperations.Verify,
                    policy),
                Is.SameAs(provider));
        }
        else
        {
            var exception = Assert.Throws<InvalidOperationException>(() => factory.GetRequiredProvider(
                MlDsa65SignatureProvider.Algorithm,
                SignatureProviderOperations.Verify,
                policy));
            Assert.That(exception!.Message, Does.Contain("is unavailable"));
        }
    }

    [Test]
    public void Provider_capabilities_match_versioned_envelope_signature_metadata()
    {
        var metadata = new HipProtocolSignature(
            HipProtocolSignature.OriginAndIntegrityScope,
            "mldsa-key-1",
            MlDsa65SignatureProvider.Algorithm,
            SignatureAlgorithmFamily.PostQuantum,
            HipProtocolSignature.Rfc8785Canonicalization,
            new string('a', 64));
        var capabilities = new MlDsa65SignatureProvider().Capabilities;

        Assert.Multiple(() =>
        {
            Assert.That(capabilities.Algorithm, Is.EqualTo(metadata.Algorithm));
            Assert.That(capabilities.AlgorithmFamily, Is.EqualTo(metadata.AlgorithmFamily));
            Assert.That(metadata.Scope, Is.EqualTo(HipProtocolSignature.OriginAndIntegrityScope));
            Assert.That(capabilities.EstablishesSafetyOrReputation, Is.False);
        });
    }

    [Test]
    public void Application_registration_includes_mldsa65_without_replacing_development_identity_crypto()
    {
        var services = new ServiceCollection();
        services.AddHipApplication(allowDevelopmentCryptoProvider: true);
        using var provider = services.BuildServiceProvider();

        var signatureProviders = provider.GetServices<IHipSignatureProvider>().ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(
                signatureProviders.Select(item => item.Capabilities.Algorithm),
                Does.Contain(MlDsa65SignatureProvider.Algorithm));
            Assert.That(
                provider.GetRequiredService<HIP.Application.Identity.IHipCryptoProvider>(),
                Is.TypeOf<HIP.Application.Identity.DevelopmentHipCryptoProvider>());
        });
    }

    private static string RewrapPublicKeyPem(string pem, int lineLength)
    {
        var payload = string.Concat(pem
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(line => !line.StartsWith("-----", StringComparison.Ordinal)));
        var lines = new List<string>();
        for (var offset = 0; offset < payload.Length; offset += lineLength)
        {
            lines.Add(payload.Substring(offset, Math.Min(lineLength, payload.Length - offset)));
        }

        return $"-----BEGIN PUBLIC KEY-----\r\n{string.Join("\r\n", lines)}\r\n-----END PUBLIC KEY-----";
    }
}
