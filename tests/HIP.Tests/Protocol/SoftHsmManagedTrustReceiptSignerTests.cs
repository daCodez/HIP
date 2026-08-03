using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using HIP.Application;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Infrastructure;
using HIP.Infrastructure.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HIP.Tests.Protocol;

#pragma warning disable SYSLIB5006

[NonParallelizable]
public sealed class SoftHsmManagedTrustReceiptSignerTests
{
    [Test]
    public void Public_key_encoding_produces_standard_ml_dsa_65_subject_public_key_info()
    {
        RequireMlDsa();
        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var reader = new AsnReader(key.ExportSubjectPublicKeyInfo(), AsnEncodingRules.DER);
        var subjectPublicKeyInfo = reader.ReadSequence();
        var algorithm = subjectPublicKeyInfo.ReadSequence();

        Assert.That(
            algorithm.ReadObjectIdentifier(),
            Is.EqualTo(SoftHsmPkcs11Client.MlDsa65ObjectIdentifier));
        algorithm.ThrowIfNotEmpty();
        var rawPublicKey = subjectPublicKeyInfo.ReadBitString(out var unusedBitCount);
        subjectPublicKeyInfo.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        var encoded = SoftHsmPkcs11Client.EncodePublicKey(rawPublicKey);
        using var imported = MLDsa.ImportFromPem(encoded);

        Assert.Multiple(() =>
        {
            Assert.That(unusedBitCount, Is.Zero);
            Assert.That(imported.Algorithm, Is.EqualTo(MLDsaAlgorithm.MLDsa65));
            Assert.That(imported.ExportSubjectPublicKeyInfo(), Is.EqualTo(key.ExportSubjectPublicKeyInfo()));
        });
    }

    [Test]
    public async Task Soft_hsm_signer_bootstraps_public_lifecycle_state_and_returns_verified_signature()
    {
        RequireMlDsa();
        var repository = new InMemorySigningKeyLifecycleRepository();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISigningKeyLifecycleRepository>(repository);
        services.AddSingleton<IAuditLogRepository>(repository);
        services.AddHipApplication(allowDevelopmentCryptoProvider: false);
        services.RemoveAll<IManagedTrustReceiptSigner>();
        services.AddSingleton(new SoftHsmManagedSignerIdentityOptions(
            "hip:authority:softhsm-test",
            "softhsm-test-key-1",
            "HIP SoftHSM Test Authority",
            "system:softhsm-test"));
        services.AddSingleton<ISoftHsmPkcs11Client, InMemorySoftHsmClient>();
        services.AddScoped<IManagedTrustReceiptSigner, SoftHsmManagedTrustReceiptSigner>();

        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var signer = scope.ServiceProvider.GetRequiredService<IManagedTrustReceiptSigner>();
        var signingKey = await signer.GetSigningKeyAsync(CancellationToken.None);
        const string contentHash = "sha256:0123456789abcdef";
        var signature = await signer.SignHashAsync(signingKey, contentHash, CancellationToken.None);
        var ring = await repository.GetAsync(signingKey.IssuerId, CancellationToken.None);
        var storedKey = ring!.GetRequiredKey(signingKey.KeyId);

        Assert.Multiple(() =>
        {
            Assert.That(signingKey.Algorithm, Is.EqualTo(MlDsa65SignatureProvider.Algorithm));
            Assert.That(signingKey.AlgorithmFamily, Is.EqualTo(HIP.Domain.Identity.SignatureAlgorithmFamily.PostQuantum));
            Assert.That(storedKey.PublicKey, Does.StartWith("-----BEGIN PUBLIC KEY-----"));
            Assert.That(storedKey.PublicKey, Does.Not.Contain("PRIVATE KEY"));
            Assert.That(
                new MlDsa65SignatureProvider().VerifySignature(contentHash, signature, storedKey.PublicKey),
                Is.True);
        });
    }

    [Test]
    public void Soft_hsm_options_reject_relative_secret_and_library_paths()
    {
        var options = new SoftHsmManagedSigningOptions
        {
            LibraryPath = "libsofthsm2.so",
            UserPinFilePath = "pin",
            TokenLabel = "hip-signing",
            KeyLabel = "hip-mldsa-65"
        };

        Assert.That(options.Validate(), Is.EqualTo("SoftHSM library path must be absolute."));
    }

    [Test]
    public void Infrastructure_selects_soft_hsm_provider_and_exact_signer_allowlists()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:HipDatabase"] = "Host=localhost;Database=hip;Username=hip;Password=test",
                ["ConnectionStrings:redis"] = "localhost:6379,abortConnect=false",
                ["HipManagedSigning:Provider"] = "SoftHsm",
                ["HipManagedSigning:ExpectedIssuerId"] = "hip:authority:softhsm",
                ["HipManagedSigning:ExpectedKeyId"] = "hip-mldsa-65-1",
                ["HipManagedSigning:ExpectedAlgorithm"] = "ML-DSA-65",
                ["HipManagedSigning:SoftHsm:LibraryPath"] = Path.GetFullPath("libsofthsm2.so"),
                ["HipManagedSigning:SoftHsm:TokenLabel"] = "hip-signing",
                ["HipManagedSigning:SoftHsm:UserPinFilePath"] = Path.GetFullPath("user-pin"),
                ["HipManagedSigning:SoftHsm:KeyLabel"] = "hip-mldsa-65"
            })
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHipApplication(allowDevelopmentCryptoProvider: false);
        services.AddHipInfrastructure(configuration, isLocalDevelopment: true);
        using var provider = services.BuildServiceProvider();

        Assert.Multiple(() =>
        {
            Assert.That(
                services.Last(descriptor => descriptor.ServiceType == typeof(IManagedTrustReceiptSigner))
                    .ImplementationType,
                Is.EqualTo(typeof(SoftHsmManagedTrustReceiptSigner)));
            Assert.That(
                services.Last(descriptor => descriptor.ServiceType == typeof(IManagedIdentityKeyProvider))
                    .ImplementationType,
                Is.EqualTo(typeof(SoftHsmManagedIdentityKeyProvider)));
            Assert.That(
                provider.GetRequiredService<HipTrustReceiptIssuerPolicy>()
                    .IsAuthorized("hip:authority:softhsm", "hip-mldsa-65-1"),
                Is.True);
            Assert.That(
                provider.GetRequiredService<HIP.Application.Certificates.DomainCertificateSigningAuthorityPolicy>()
                    .IsAuthorized("hip:authority:softhsm", "hip-mldsa-65-1"),
                Is.True);
        });
    }

    [Test]
    public void Managed_identity_key_labels_are_stable_distinct_and_do_not_expose_identity_text()
    {
        var first = SoftHsmManagedIdentityKeyProvider.KeyLabel("hip:web:example.com", "default");
        var same = SoftHsmManagedIdentityKeyProvider.KeyLabel("hip:web:example.com", "default");
        var different = SoftHsmManagedIdentityKeyProvider.KeyLabel("hip:web:other.example", "default");

        Assert.Multiple(() =>
        {
            Assert.That(first, Is.EqualTo(same));
            Assert.That(first, Is.Not.EqualTo(different));
            Assert.That(first, Does.Match("^hip-identity-[0-9a-f]{32}$"));
            Assert.That(first, Does.Not.Contain("example.com"));
        });
    }

    private static void RequireMlDsa()
    {
        if (!MLDsa.IsSupported)
        {
            Assert.Ignore("The current test platform does not provide ML-DSA.");
        }
    }

    private sealed class InMemorySoftHsmClient : ISoftHsmPkcs11Client, IDisposable
    {
        private readonly MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        public Task<SoftHsmSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new SoftHsmSigningKey(key.ExportSubjectPublicKeyInfoPem()));
        }

        public Task<SoftHsmSigningKey> GetOrCreateSigningKeyAsync(
            string keyLabel,
            CancellationToken cancellationToken) => GetSigningKeyAsync(cancellationToken);

        public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(key.SignData(data.ToArray()));
        }

        public void Dispose() => key.Dispose();
    }
}

#pragma warning restore SYSLIB5006
