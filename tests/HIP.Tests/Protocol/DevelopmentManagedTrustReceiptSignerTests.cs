using HIP.Application;
using HIP.Application.Certificates;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace HIP.Tests.Protocol;

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
        bool allowDevelopmentCryptoProvider)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISigningKeyLifecycleRepository>(repository);
        services.AddSingleton<IAuditLogRepository>(repository);
        services.AddHipApplication(allowDevelopmentCryptoProvider);
        return services;
    }
}
