using HIP.Application;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

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
        services.AddHipApplication();
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
}
