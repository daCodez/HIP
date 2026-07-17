using HIP.Application;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

public sealed class HipSignatureProviderFactoryTests
{
    [Test]
    public void Development_policy_selects_explicit_available_provider_with_required_capabilities()
    {
        var developmentProvider = new DevelopmentHipCryptoProvider();
        var factory = new HipSignatureProviderFactory([developmentProvider]);
        var policy = SignatureProviderRuntimePolicy.ForDevelopment(DevelopmentHipCryptoProvider.Algorithm);

        var provider = factory.GetRequiredProvider(
            DevelopmentHipCryptoProvider.Algorithm,
            SignatureProviderOperations.Sign | SignatureProviderOperations.Verify,
            policy);

        Assert.Multiple(() =>
        {
            Assert.That(provider, Is.SameAs(developmentProvider));
            Assert.That(provider.Capabilities.AlgorithmFamily, Is.EqualTo(SignatureAlgorithmFamily.Unknown));
            Assert.That(provider.Capabilities.IsAvailable, Is.True);
            Assert.That(provider.Capabilities.IsDevelopmentOnly, Is.True);
            Assert.That(
                provider.Capabilities.SupportedOperations,
                Is.EqualTo(SignatureProviderOperations.Sign | SignatureProviderOperations.Verify));
        });
    }

    [Test]
    public void Provider_exposes_sign_and_verify_operations_through_agile_interface()
    {
        IHipSignatureProvider provider = new DevelopmentHipCryptoProvider();
        var keyPair = ((IHipCryptoProvider)provider).GenerateKeyPair();

        var signature = provider.SignHash("sha256:abc", keyPair.PrivateKey);

        Assert.That(provider.VerifySignature("sha256:abc", signature, keyPair.PublicKey), Is.True);
    }

    [Test]
    public void Unknown_algorithm_fails_closed_without_provider_fallback()
    {
        var factory = new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]);
        var policy = SignatureProviderRuntimePolicy.ForDevelopment("ML-DSA-65");

        var exception = Assert.Throws<NotSupportedException>(() => factory.GetRequiredProvider(
            "ML-DSA-65",
            SignatureProviderOperations.Verify,
            policy));

        Assert.That(exception!.Message, Does.Contain("No HIP signature provider is registered"));
    }

    [Test]
    public void Algorithm_not_allowlisted_by_runtime_policy_fails_closed()
    {
        var factory = new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]);
        var policy = SignatureProviderRuntimePolicy.ForDevelopment("ML-DSA-65");

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetRequiredProvider(
            DevelopmentHipCryptoProvider.Algorithm,
            SignatureProviderOperations.Verify,
            policy));

        Assert.That(exception!.Message, Does.Contain("is disallowed by runtime policy"));
    }

    [Test]
    public void Unavailable_provider_fails_closed()
    {
        var provider = new TestSignatureProvider(new SignatureProviderCapabilities(
            "ML-DSA-65",
            SignatureAlgorithmFamily.PostQuantum,
            SignatureProviderOperations.Sign | SignatureProviderOperations.Verify,
            IsAvailable: false,
            IsDevelopmentOnly: false));
        var factory = new HipSignatureProviderFactory([provider]);
        var policy = SignatureProviderRuntimePolicy.ForProduction("ML-DSA-65");

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetRequiredProvider(
            "ML-DSA-65",
            SignatureProviderOperations.Verify,
            policy));

        Assert.That(exception!.Message, Does.Contain("is unavailable"));
    }

    [Test]
    public void Provider_missing_required_operation_fails_closed()
    {
        var provider = new TestSignatureProvider(new SignatureProviderCapabilities(
            "verify-only",
            SignatureAlgorithmFamily.Classical,
            SignatureProviderOperations.Verify,
            IsAvailable: true,
            IsDevelopmentOnly: false));
        var factory = new HipSignatureProviderFactory([provider]);
        var policy = SignatureProviderRuntimePolicy.ForProduction("verify-only");

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetRequiredProvider(
            "verify-only",
            SignatureProviderOperations.Sign,
            policy));

        Assert.That(exception!.Message, Does.Contain("does not support the required operations"));
    }

    [Test]
    public void Production_policy_cannot_select_development_provider_even_when_allowlisted()
    {
        var factory = new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]);
        var policy = SignatureProviderRuntimePolicy.ForProduction(DevelopmentHipCryptoProvider.Algorithm);

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetRequiredProvider(
            DevelopmentHipCryptoProvider.Algorithm,
            SignatureProviderOperations.Verify,
            policy));

        Assert.That(exception!.Message, Does.Contain("development-only"));
    }

    [Test]
    public void Versioned_envelope_algorithm_selects_matching_provider_without_implying_safety()
    {
        var fixture = File.ReadAllText(Path.Combine(
            RepositoryRoot(), "tests", "HIP.Tests", "Protocol", "Fixtures", "hip-envelope-v1.json"));
        var envelope = HipProtocolEnvelopeJson.Deserialize(fixture);
        var factory = new HipSignatureProviderFactory([new DevelopmentHipCryptoProvider()]);
        var policy = SignatureProviderRuntimePolicy.ForDevelopment(envelope.Signature.Algorithm);

        var provider = factory.GetRequiredProvider(
            envelope.Signature.Algorithm,
            SignatureProviderOperations.Verify,
            policy);

        Assert.Multiple(() =>
        {
            Assert.That(provider.Capabilities.Algorithm, Is.EqualTo(envelope.Signature.Algorithm));
            Assert.That(provider.Capabilities.AlgorithmFamily, Is.EqualTo(envelope.Signature.AlgorithmFamily));
            Assert.That(provider.Capabilities.EstablishesSafetyOrReputation, Is.False);
        });
    }

    [Test]
    public void Application_registration_exposes_factory_and_development_provider_interfaces()
    {
        var services = new ServiceCollection();
        services.AddHipApplication();
        using var provider = services.BuildServiceProvider();

        var factory = provider.GetRequiredService<IHipSignatureProviderFactory>();
        var signatureProvider = provider.GetRequiredService<IHipSignatureProvider>();
        var cryptoProvider = provider.GetRequiredService<IHipCryptoProvider>();

        Assert.Multiple(() =>
        {
            Assert.That(factory, Is.TypeOf<HipSignatureProviderFactory>());
            Assert.That(signatureProvider, Is.SameAs(cryptoProvider));
        });
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "HIP.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }

    private sealed class TestSignatureProvider(SignatureProviderCapabilities capabilities) : IHipSignatureProvider
    {
        public SignatureProviderCapabilities Capabilities { get; } = capabilities;

        public string SignHash(string contentHash, string privateKey) => "test-signature";

        public bool VerifySignature(string contentHash, string signatureValue, string publicKey) => true;
    }
}
