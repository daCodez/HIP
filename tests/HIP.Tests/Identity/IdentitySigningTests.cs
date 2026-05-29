using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Domain.Identity;

namespace HIP.Tests.Identity;

public sealed class IdentitySigningTests
{
    [Test]
    public async Task Identity_can_be_created()
    {
        var service = Service(out _);

        var response = await service.RegisterAsync(new IdentityRegistrationRequest(IdentitySubjectType.Domain, "example.com", "example.com"), CancellationToken.None);

        Assert.That(response.Identity.IdentityId, Does.StartWith("hip:domain:"));
        Assert.That(response.Identity.KeyAlgorithm, Is.EqualTo(DevelopmentHipCryptoProvider.Algorithm));
        Assert.That(response.Identity.VerificationStatus, Is.EqualTo(VerificationStatus.Pending));
    }

    [Test]
    public void Content_hash_is_stable()
    {
        var crypto = new DevelopmentHipCryptoProvider();

        var first = crypto.HashContent("same content");
        var second = crypto.HashContent("same content");

        Assert.That(first, Is.EqualTo(second));
        Assert.That(first, Does.StartWith("sha256:"));
    }

    [Test]
    public async Task Signature_verifies_with_matching_key()
    {
        var service = Service(out var crypto);
        var identity = await service.RegisterAsync(new IdentityRegistrationRequest(IdentitySubjectType.App, "HIP Test App", "app:test"), CancellationToken.None);
        var hash = crypto.HashContent("signed payload");

        var signature = await service.SignAsync(new SignContentRequest(identity.Identity.IdentityId, hash, identity.DevelopmentPrivateKey!, null), CancellationToken.None);
        var result = await service.VerifyAsync(new VerifySignatureRequest(identity.Identity.IdentityId, hash, signature.SignatureValue), CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task Signature_fails_with_wrong_content_hash()
    {
        var service = Service(out var crypto);
        var identity = await service.RegisterAsync(new IdentityRegistrationRequest(IdentitySubjectType.Website, "example.com", "example.com"), CancellationToken.None);
        var signature = await service.SignAsync(new SignContentRequest(identity.Identity.IdentityId, crypto.HashContent("original"), identity.DevelopmentPrivateKey!, null), CancellationToken.None);

        var result = await service.VerifyAsync(new VerifySignatureRequest(identity.Identity.IdentityId, crypto.HashContent("changed"), signature.SignatureValue), CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task Verification_result_includes_plain_english_reason()
    {
        var service = Service(out var crypto);
        var identity = await service.RegisterAsync(new IdentityRegistrationRequest(IdentitySubjectType.ContentPublisher, "Publisher", "publisher"), CancellationToken.None);
        var hash = crypto.HashContent("content");
        var signature = await service.SignAsync(new SignContentRequest(identity.Identity.IdentityId, hash, identity.DevelopmentPrivateKey!, null), CancellationToken.None);

        var result = await service.VerifyAsync(new VerifySignatureRequest(identity.Identity.IdentityId, hash, signature.SignatureValue), CancellationToken.None);

        Assert.That(result.Reason, Does.Contain("Safety still depends on reputation and risk scoring"));
    }

    [Test]
    public async Task Domain_verification_request_can_be_created()
    {
        var service = new InMemoryDomainVerificationService();

        var request = await service.StartAsync("Example.com", VerificationMethod.DnsTxt, CancellationToken.None);

        Assert.That(request.Domain, Is.EqualTo("example.com"));
        Assert.That(request.Status, Is.EqualTo(VerificationStatus.Pending));
        Assert.That(request.Token, Does.StartWith("hip-domain-verification="));
    }

    [Test]
    public async Task Public_lookup_shows_signed_identity_status()
    {
        var lookup = await new PublicDomainLookupService().LookupDomainAsync("verified-example.com", CancellationToken.None);

        Assert.That(lookup.SignedIdentityStatus, Is.EqualTo("PostQuantumSignaturePresent"));
        Assert.That(lookup.IdentityVerificationStatus, Is.EqualTo("Verified"));
        Assert.That(lookup.SignatureValid, Is.True);
    }

    [Test]
    public async Task Badge_output_includes_verification_status()
    {
        var badge = await new TrustBadgeService(new PublicDomainLookupService()).GetDomainBadgeAsync("verified-example.com", CancellationToken.None);

        Assert.That(badge.IdentityVerificationStatus, Is.EqualTo("Verified"));
        Assert.That(badge.SignatureValid, Is.True);
    }

    [Test]
    public void Placeholder_crypto_is_clearly_marked_non_production()
    {
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();

        Assert.That(keyPair.IsProductionSafe, Is.False);
        Assert.That(DevelopmentHipCryptoProvider.Algorithm, Does.Contain("Development"));
        Assert.That(DevelopmentHipCryptoProvider.Algorithm, Does.Contain("Placeholder"));
    }

    private static HipIdentityService Service(out DevelopmentHipCryptoProvider crypto)
    {
        crypto = new DevelopmentHipCryptoProvider();
        return new HipIdentityService(crypto, new InMemoryHipIdentityRepository());
    }
}
