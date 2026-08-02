using HIP.Application;
using HIP.Application.Certificates;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

[NonParallelizable]
public sealed class DevelopmentManagedTrustReceiptSignerTests
{
    [Test]
    public async Task Development_registration_bootstraps_authorized_durable_public_signing_state()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var services = Services(repository, allowDevelopmentCryptoProvider: true);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        var signer = scope.ServiceProvider.GetRequiredService<IManagedTrustReceiptSigner>();
        var key = await signer.GetSigningKeyAsync(CancellationToken.None);
        var signature = await signer.SignHashAsync(
            key,
            "sha256:0123456789abcdef",
            CancellationToken.None);
        var identity = await repository.GetRegisteredIdentityAsync(
            key.IssuerId,
            CancellationToken.None);
        var ring = await repository.GetAsync(key.IssuerId, CancellationToken.None);
        var storedKey = ring!.GetRequiredKey(key.KeyId);
        var signatureProvider = provider.GetServices<IHipSignatureProvider>()
            .Single(candidate => candidate.Capabilities.Algorithm == key.Algorithm);

        Assert.Multiple(() =>
        {
            Assert.That(signer, Is.Not.TypeOf<UnavailableManagedTrustReceiptSigner>());
            Assert.That(identity, Is.Not.Null);
            Assert.That(identity!.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
            Assert.That(storedKey.Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(storedKey.PublicKey, Does.StartWith("dev-public:"));
            Assert.That(storedKey.PublicKey, Does.Not.Contain("dev-private:"));
            Assert.That(signatureProvider.VerifySignature(
                "sha256:0123456789abcdef",
                signature,
                storedKey.PublicKey), Is.True);
            Assert.That(
                provider.GetRequiredService<HipTrustReceiptIssuerPolicy>()
                    .IsAuthorized(key.IssuerId, key.KeyId),
                Is.True);
            Assert.That(
                provider.GetRequiredService<DomainCertificateSigningAuthorityPolicy>()
                    .IsAuthorized(key.IssuerId, key.KeyId),
                Is.True);
        });
    }

    [Test]
    public async Task Development_certificate_signer_self_verifies_eligible_certificate()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var services = Services(repository, allowDevelopmentCryptoProvider: true);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var now = DateTimeOffset.UtcNow.ToUniversalTime();
        var evaluation = new DomainCertificatePolicyEvaluationResult(
            "example.com",
            DomainCertificateLevel.Verified,
            DomainCertificatePolicy.V1.Version,
            DomainCertificatePolicyDecision.Eligible,
            "This domain completed HIP identity and baseline security verification.",
            [],
            now.AddMinutes(-1));
        var draft = new DomainCertificateSigningDraft(
            "hip-domain-cert-development-integration",
            1,
            "example.com",
            DomainCertificateLevel.Verified,
            "Example Site",
            "Example Organization",
            null,
            [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            DomainCertificatePublicRiskClassification.Low,
            [],
            "https://hiptrust.com/api/v1/certificates/hip-domain-cert-development-integration/status",
            "https://hiptrust.com/certificate/hip-domain-cert-development-integration",
            now.AddMinutes(-10),
            null,
            evaluation);

        var result = await scope.ServiceProvider
            .GetRequiredService<IDomainCertificateSigningService>()
            .SignAsync(draft, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.Signed));
            Assert.That(result.Certificate, Is.Not.Null);
            Assert.That(result.Certificate!.Signature.Value, Is.Not.Empty);
        });
    }
    [Test]
    public async Task Development_restart_rotates_process_key_and_preserves_historical_public_key()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var firstKey = await ResolveKeyAsync(repository);
        var secondKey = await ResolveKeyAsync(repository);
        var ring = await repository.GetAsync(firstKey.IssuerId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(secondKey.IssuerId, Is.EqualTo(firstKey.IssuerId));
            Assert.That(secondKey.KeyId, Is.Not.EqualTo(firstKey.KeyId));
            Assert.That(ring, Is.Not.Null);
            Assert.That(ring!.Keys, Has.Count.EqualTo(2));
            Assert.That(ring.GetRequiredKey(firstKey.KeyId).Status, Is.EqualTo(SigningKeyStatus.Retiring));
            Assert.That(ring.GetRequiredKey(secondKey.KeyId).Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(ring.GetRequiredKey(firstKey.KeyId).CanVerifyHistoricalSignature, Is.True);
        });
    }

    [Test]
    public async Task Development_service_scopes_do_not_retire_each_others_signing_keys()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var webServices = Services(
            repository,
            allowDevelopmentCryptoProvider: true,
            developmentSigningAuthorityScope: "web");
        await using var webProvider = webServices.BuildServiceProvider();
        await using var webScope = webProvider.CreateAsyncScope();
        var webSigner = webScope.ServiceProvider.GetRequiredService<IManagedTrustReceiptSigner>();
        var initialWebKey = await webSigner.GetSigningKeyAsync(CancellationToken.None);

        var apiServices = Services(
            repository,
            allowDevelopmentCryptoProvider: true,
            developmentSigningAuthorityScope: "api");
        await using var apiProvider = apiServices.BuildServiceProvider();
        await using var apiScope = apiProvider.CreateAsyncScope();
        var apiKey = await apiScope.ServiceProvider
            .GetRequiredService<IManagedTrustReceiptSigner>()
            .GetSigningKeyAsync(CancellationToken.None);
        var currentWebKey = await webSigner.GetSigningKeyAsync(CancellationToken.None);

        var webRing = await repository.GetAsync(initialWebKey.IssuerId, CancellationToken.None);
        var apiRing = await repository.GetAsync(apiKey.IssuerId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(initialWebKey.IssuerId, Is.EqualTo("hip:development:web-certificate-authority"));
            Assert.That(apiKey.IssuerId, Is.EqualTo("hip:development:api-certificate-authority"));
            Assert.That(apiKey.IssuerId, Is.Not.EqualTo(initialWebKey.IssuerId));
            Assert.That(currentWebKey, Is.EqualTo(initialWebKey));
            Assert.That(webRing!.GetRequiredKey(initialWebKey.KeyId).Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(apiRing!.GetRequiredKey(apiKey.KeyId).Status, Is.EqualTo(SigningKeyStatus.Active));
            Assert.That(
                webProvider.GetRequiredService<HipTrustReceiptIssuerPolicy>()
                    .IsAuthorized(initialWebKey.IssuerId, initialWebKey.KeyId),
                Is.True);
            Assert.That(
                apiProvider.GetRequiredService<HipTrustReceiptIssuerPolicy>()
                    .IsAuthorized(apiKey.IssuerId, apiKey.KeyId),
                Is.True);
        });
    }

    [Test]
    public void Production_registration_keeps_managed_signing_unavailable_and_unauthorized()
    {
        var services = Services(
            new InMemorySigningKeyLifecycleRepository(),
            allowDevelopmentCryptoProvider: false);
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var signer = scope.ServiceProvider.GetRequiredService<IManagedTrustReceiptSigner>();

        Assert.Multiple(() =>
        {
            Assert.That(signer, Is.TypeOf<UnavailableManagedTrustReceiptSigner>());
            Assert.That(
                provider.GetRequiredService<HipTrustReceiptIssuerPolicy>()
                    .IsAuthorized("hip:development:certificate-authority", "any-key"),
                Is.False);
            Assert.That(
                provider.GetRequiredService<DomainCertificateSigningAuthorityPolicy>()
                    .IsAuthorized("hip:development:certificate-authority", "any-key"),
                Is.False);
        });
    }

    private static async Task<HipManagedTrustReceiptSigningKey> ResolveKeyAsync(
        InMemorySigningKeyLifecycleRepository repository)
    {
        var services = Services(repository, allowDevelopmentCryptoProvider: true);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        return await scope.ServiceProvider
            .GetRequiredService<IManagedTrustReceiptSigner>()
            .GetSigningKeyAsync(CancellationToken.None);
    }

    private static ServiceCollection Services(
        InMemorySigningKeyLifecycleRepository repository,
        bool allowDevelopmentCryptoProvider,
        string? developmentSigningAuthorityScope = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISigningKeyLifecycleRepository>(repository);
        services.AddSingleton<IAuditLogRepository>(repository);
        services.AddHipApplication(
            allowDevelopmentCryptoProvider,
            developmentSigningAuthorityScope);
        return services;
    }
}
