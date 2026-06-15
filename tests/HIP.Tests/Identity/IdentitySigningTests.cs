using HIP.Application.Browser;
using HIP.Application.Identity;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Scalability;
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
    public async Task Website_identity_can_be_registered()
    {
        var service = WebsiteService();

        var response = await service.RegisterAsync(new WebsiteIdentityRegistrationRequest("Example.com", "Example", VerificationMethod.WellKnownHipJson), CancellationToken.None);

        Assert.That(response.WebsiteIdentity.Domain, Is.EqualTo("example.com"));
        Assert.That(response.WebsiteIdentity.HipIdentityId, Is.EqualTo("hip:web:example.com"));
        Assert.That(response.WebsiteIdentity.PublicKeys.Single().Algorithm, Is.EqualTo(DevelopmentHipCryptoProvider.Algorithm));
        Assert.That(response.Warning, Does.Contain("non-production placeholder crypto provider"));
    }

    [Test]
    public async Task Well_known_verification_placeholder_works()
    {
        var service = WebsiteService();
        var registered = await service.RegisterAsync(new WebsiteIdentityRegistrationRequest("wellknown.example", "Well Known", VerificationMethod.WellKnownHipJson), CancellationToken.None);

        var verified = await service.VerifyAsync(new WebsiteVerificationRequest("wellknown.example", VerificationMethod.WellKnownHipJson, registered.VerificationRequest.Token), CancellationToken.None);
        var document = await service.BuildWellKnownDocumentAsync("wellknown.example", CancellationToken.None);

        Assert.That(verified.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
        Assert.That(document.Domain, Is.EqualTo("wellknown.example"));
        Assert.That(document.PublicKeys.Single().KeyId, Is.EqualTo("default"));
    }

    [Test]
    public async Task Dns_verification_placeholder_works()
    {
        var service = WebsiteService();
        var registered = await service.RegisterAsync(new WebsiteIdentityRegistrationRequest("dns.example", "DNS Example", VerificationMethod.DnsTxt), CancellationToken.None);

        var verified = await service.VerifyAsync(new WebsiteVerificationRequest("dns.example", VerificationMethod.DnsTxt, registered.VerificationRequest.Token), CancellationToken.None);

        Assert.That(verified.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
        Assert.That(registered.VerificationRequest.Token, Does.StartWith("hip-domain-verification="));
    }

    [Test]
    public async Task Signature_verification_result_can_be_returned()
    {
        var repository = new InMemoryHipIdentityRepository();
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = new HipIdentity("hip:web:signed.example", IdentitySubjectType.Website, "signed.example", keyPair.PublicKey, keyPair.Algorithm, VerificationStatus.Verified, DateTimeOffset.UtcNow, "signed.example");
        await repository.SaveAsync(identity, CancellationToken.None);
        var signatureService = new HipSignatureService(crypto, repository);
        var hash = crypto.HashContent("homepage");
        var signature = crypto.SignHash(hash, keyPair.PrivateKey);

        var result = await signatureService.VerifyAsync(new HipSignatureVerificationRequest(identity.IdentityId, hash, signature, "Trusted"), CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.SignedIdentityStatus, Is.EqualTo("Verified"));
        Assert.That(result.Reason, Does.Contain("HIP knows who signed it"));
    }

    [Test]
    public async Task Valid_signature_does_not_automatically_mark_site_safe()
    {
        var repository = new InMemoryHipIdentityRepository();
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = new HipIdentity("hip:web:low-rep.example", IdentitySubjectType.Website, "low-rep.example", keyPair.PublicKey, keyPair.Algorithm, VerificationStatus.Verified, DateTimeOffset.UtcNow, "low-rep.example");
        await repository.SaveAsync(identity, CancellationToken.None);
        var signatureService = new HipSignatureService(crypto, repository);
        var hash = crypto.HashContent("homepage");
        var signature = crypto.SignHash(hash, keyPair.PrivateKey);

        var result = await signatureService.VerifyAsync(new HipSignatureVerificationRequest(identity.IdentityId, hash, signature, "Low"), CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.FinalRiskStatus, Is.EqualTo("Caution"));
        Assert.That(result.Reason, Does.Contain("does not automatically mean safe"));
    }

    [Test]
    public async Task Public_lookup_shows_signed_identity_status()
    {
        var repository = await SeedStoredBrowserScanAsync("verified-example.com");
        var lookup = await new PublicDomainLookupService(repository).LookupDomainAsync("verified-example.com", CancellationToken.None);

        Assert.That(lookup.SignedIdentityStatus, Is.EqualTo("PostQuantumSignaturePresent"));
        Assert.That(lookup.IdentityVerificationStatus, Is.EqualTo("Verified"));
        Assert.That(lookup.SignatureValid, Is.True);
    }

    [Test]
    public async Task Badge_output_includes_verification_status()
    {
        var repository = await SeedStoredBrowserScanAsync("verified-example.com");
        var badge = await new TrustBadgeService(new PublicDomainLookupService(repository)).GetDomainBadgeAsync("verified-example.com", CancellationToken.None);

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

    /// <summary>
    /// Ensures dependency injection cannot accidentally use the placeholder signing provider outside Development.
    /// </summary>
    [Test]
    public void Placeholder_crypto_refuses_non_development_environment()
    {
        var options = new DevelopmentHipCryptoProviderOptions(AllowDevelopmentProvider: false);

        var exception = Assert.Throws<InvalidOperationException>(() => new DevelopmentHipCryptoProvider(options));

        Assert.That(exception!.Message, Does.Contain("cannot be used outside Development"));
    }

    private static HipIdentityService Service(out DevelopmentHipCryptoProvider crypto)
    {
        crypto = new DevelopmentHipCryptoProvider();
        return new HipIdentityService(crypto, new InMemoryHipIdentityRepository());
    }

    private static WebsiteIdentityService WebsiteService() =>
        new(new DevelopmentHipCryptoProvider(), new InMemoryHipIdentityRepository(), new InMemoryDomainVerificationService());

    private static HipSignatureService SignatureService(DevelopmentHipCryptoProvider crypto) =>
        new(crypto, new InMemoryHipIdentityRepository());

    /// <summary>
    /// Seeds a privacy-safe browser scan so signed identity lookup tests exercise the real scan-data path.
    /// </summary>
    /// <param name="domain">Domain to seed.</param>
    /// <returns>Repository containing the seeded scan result.</returns>
    private static async Task<InMemoryBrowserScanResultRepository> SeedStoredBrowserScanAsync(string domain)
    {
        var repository = new InMemoryBrowserScanResultRepository();
        var service = new BrowserScanResultService(repository, new Sha256PrivacyHashingService(), new InMemoryScanResultCache(), new InMemoryDashboardScanAggregateStore());
        await service.SaveAsync(new BrowserScanResultSaveRequest(
            domain,
            $"https://{domain}/",
            91,
            "Trusted",
            "Trusted",
            ["Stored browser scan found no dangerous links."],
            8,
            0,
            0,
            0,
            "Allow",
            new Dictionary<string, string>
            {
                ["scanMode"] = "Normal"
            }), CancellationToken.None);

        return repository;
    }
}

