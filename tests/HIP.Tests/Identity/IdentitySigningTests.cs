using HIP.Application.Browser;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Application.Reporting;
using HIP.Application.Review;
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
        Assert.That(request.Token, Is.Not.Empty);
        Assert.That(request.Token, Does.Not.Contain("hip-domain-verification="));
    }

    [Test]
    public async Task Website_identity_can_be_registered()
    {
        var service = WebsiteService();

        var response = await service.RegisterAsync(new WebsiteIdentityRegistrationRequest("Example.com", "Example", VerificationMethod.WellKnownHipJson), CancellationToken.None);

        Assert.That(response.WebsiteIdentity.Domain, Is.EqualTo("example.com"));
        Assert.That(response.WebsiteIdentity.HipIdentityId, Is.EqualTo("hip:web:example.com"));
        Assert.That(response.WebsiteIdentity.PublicKeys.Single().Algorithm, Is.EqualTo(DevelopmentHipCryptoProvider.Algorithm));
        Assert.That(response.DevelopmentPrivateKey, Is.Not.Null.And.Not.Empty);
        Assert.That(response.IsRecovery, Is.False);
        Assert.That(response.RequiresSigningKeyRotation, Is.False);
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
        Assert.That(registered.VerificationRequest.Token, Is.Not.Empty);
        Assert.That(registered.VerificationRequest.Token, Does.Not.Contain("hip-domain-verification="));
    }

    [Test]
    public async Task Website_verification_rejects_a_challenge_from_a_different_method()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var domainService = new InMemoryDomainVerificationService();
        var crypto = new DevelopmentHipCryptoProvider();
        var audit = new AuditLogService(repository);
        var service = new WebsiteIdentityService(
            crypto,
            repository,
            domainService,
            new TestWebsiteIdentityRepository(),
            audit,
            SigningKeyLifecycle(repository),
            repository);
        await service.RegisterAsync(
            new WebsiteIdentityRegistrationRequest("method-bound.example", "Method Bound", VerificationMethod.DnsTxt),
            CancellationToken.None);
        var unrelated = await domainService.StartAsync(
            "method-bound.example",
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);

        Assert.ThrowsAsync<WebsiteIdentityRegistrationConflictException>(() =>
            service.VerifyAsync(
                new WebsiteVerificationRequest(
                    "method-bound.example",
                    VerificationMethod.WellKnownHipJson,
                    unrelated.Token),
                CancellationToken.None));
        var current = await service.GetAsync("method-bound.example", CancellationToken.None);

        Assert.That(current!.VerificationStatus, Is.EqualTo(VerificationStatus.Pending));
    }

    [Test]
    public async Task Signature_verification_result_can_be_returned()
    {
        var repository = new InMemoryHipIdentityRepository();
        var crypto = new DevelopmentHipCryptoProvider();
        var keyPair = crypto.GenerateKeyPair();
        var identity = new HipIdentity("hip:web:signed.example", IdentitySubjectType.Website, "signed.example", keyPair.PublicKey, keyPair.Algorithm, VerificationStatus.Verified, DateTimeOffset.UtcNow, "signed.example");
        await repository.SaveAsync(identity, CancellationToken.None);
        var lifecycle = SigningKeyLifecycle();
        await RegisterDefaultKeyAsync(lifecycle, identity, keyPair);
        var signatureService = new HipSignatureService(crypto, repository, lifecycle);
        var hash = crypto.HashContent("homepage");
        var signature = crypto.SignHash(hash, keyPair.PrivateKey);

        var result = await signatureService.VerifyAsync(new HipSignatureVerificationRequest(
            identity.IdentityId, hash, signature, "Trusted", HipIdentityService.InitialSigningKeyId), CancellationToken.None);

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
        var lifecycle = SigningKeyLifecycle();
        await RegisterDefaultKeyAsync(lifecycle, identity, keyPair);
        var signatureService = new HipSignatureService(crypto, repository, lifecycle);
        var hash = crypto.HashContent("homepage");
        var signature = crypto.SignHash(hash, keyPair.PrivateKey);

        var result = await signatureService.VerifyAsync(new HipSignatureVerificationRequest(
            identity.IdentityId, hash, signature, "Low", HipIdentityService.InitialSigningKeyId), CancellationToken.None);

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
        var repository = new InMemorySigningKeyLifecycleRepository();
        return new HipIdentityService(crypto, repository, SigningKeyLifecycle(repository));
    }

    private static WebsiteIdentityService WebsiteService()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        var auditLogService = new AuditLogService(repository);
        return new(
            new DevelopmentHipCryptoProvider(),
            repository,
            new InMemoryDomainVerificationService(),
            new TestWebsiteIdentityRepository(),
            auditLogService,
            SigningKeyLifecycle(repository),
            repository);
    }

    [Test]
    public async Task Website_identity_retry_uses_stored_challenge_and_records_complete_status()
    {
        var service = WebsiteService();
        await service.RegisterAsync(
            new WebsiteIdentityRegistrationRequest("retry.example", "Retry", VerificationMethod.DnsTxt),
            CancellationToken.None);

        var retried = await service.RetryVerificationAsync(
            "retry.example", "owner-1", "Owner", CancellationToken.None);

        Assert.That(retried.VerificationStatus, Is.EqualTo(VerificationStatus.Verified));
        Assert.That(retried.LastCheckedAtUtc, Is.Not.Null);
        Assert.That(retried.LastCheckMessage, Is.Not.Empty);
    }

    [Test]
    public async Task Website_identity_revoke_updates_identity_and_writes_critical_audit_entry()
    {
        var atomicRepository = new InMemorySigningKeyLifecycleRepository();
        IHipIdentityRepository identityRepository = atomicRepository;
        var audit = new AuditLogService(atomicRepository);
        var service = new WebsiteIdentityService(
            new DevelopmentHipCryptoProvider(),
            atomicRepository,
            new InMemoryDomainVerificationService(), new TestWebsiteIdentityRepository(), audit,
            SigningKeyLifecycle(atomicRepository), atomicRepository);
        var registered = await service.RegisterAsync(
            new WebsiteIdentityRegistrationRequest("revoke.example", "Revoke", VerificationMethod.DnsTxt),
            CancellationToken.None);

        var revoked = await service.RevokeVerificationAsync(
            "revoke.example", "Ownership changed", "owner-1", "Owner", CancellationToken.None);
        var revokedAgain = await service.RevokeVerificationAsync(
            "revoke.example", "Ownership changed", "owner-1", "Owner", CancellationToken.None);
        var hipIdentity = await identityRepository.GetAsync(registered.WebsiteIdentity.HipIdentityId, CancellationToken.None);
        var auditEntries = audit.List().Where(entry => entry.Action == "domain-verification.revoked").ToArray();
        var auditEntry = auditEntries.Single();

        Assert.That(revoked.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
        Assert.That(revokedAgain, Is.EqualTo(revoked));
        Assert.That(revoked.RevokedAtUtc, Is.Not.Null);
        Assert.That(hipIdentity!.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
        Assert.That(auditEntries, Has.Length.EqualTo(1));
        Assert.That(auditEntry.ActorId, Is.EqualTo("owner-1"));
        Assert.That(auditEntry.Severity, Is.EqualTo(HIP.Domain.Audit.AuditSeverity.Critical));
        Assert.That(auditEntry.Metadata.Values, Has.None.Contains(registered.VerificationRequest.Token));
    }

    [Test]
    public async Task Website_verify_reconciles_a_preexisting_canonical_revocation_without_reactivation()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        IHipIdentityRepository identityRepository = repository;
        var domainService = new InMemoryDomainVerificationService();
        var websiteRepository = new TestWebsiteIdentityRepository();
        var service = new WebsiteIdentityService(
            new DevelopmentHipCryptoProvider(),
            repository,
            domainService,
            websiteRepository,
            new AuditLogService(repository),
            SigningKeyLifecycle(repository),
            repository);
        var registered = await service.RegisterAsync(
            new WebsiteIdentityRegistrationRequest(
                "canonical-revoked.example",
                "Canonical revoked",
                VerificationMethod.WellKnownHipJson),
            CancellationToken.None);
        var identity = await identityRepository.GetAsync(
            registered.WebsiteIdentity.HipIdentityId,
            CancellationToken.None);
        Assert.That(
            await identityRepository.TryUpdateAsync(
                identity!,
                identity! with { VerificationStatus = VerificationStatus.Revoked },
                CancellationToken.None),
            Is.True);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.VerifyAsync(
            new WebsiteVerificationRequest(
                registered.WebsiteIdentity.Domain,
                VerificationMethod.WellKnownHipJson,
                registered.VerificationRequest.Token),
            CancellationToken.None));
        var website = await websiteRepository.GetAsync(
            registered.WebsiteIdentity.Domain,
            CancellationToken.None);
        var challenge = await domainService.GetAsync(
            registered.WebsiteIdentity.Domain,
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);

        Assert.That(website!.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
        Assert.That(website.RevokedAtUtc, Is.Not.Null);
        Assert.That(challenge!.Status, Is.EqualTo(VerificationStatus.Revoked));
    }

    [Test]
    public async Task Website_identity_list_returns_registered_domains_newest_first()
    {
        var repository = new TestWebsiteIdentityRepository();
        await repository.SaveAsync(new WebsiteIdentity(
            "older.example", "hip:web:older.example", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, new DateTimeOffset(2026, 7, 12, 10, 0, 0, TimeSpan.Zero), null), CancellationToken.None);
        await repository.SaveAsync(new WebsiteIdentity(
            "newer.example", "hip:web:newer.example", [], VerificationStatus.Verified,
            VerificationMethod.DnsTxt, new DateTimeOffset(2026, 7, 13, 10, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 7, 13, 10, 5, 0, TimeSpan.Zero)), CancellationToken.None);
        var lifecycleRepository = new InMemorySigningKeyLifecycleRepository();
        var service = new WebsiteIdentityService(
            new DevelopmentHipCryptoProvider(),
            lifecycleRepository,
            new InMemoryDomainVerificationService(), repository,
            new AuditLogService(lifecycleRepository),
            SigningKeyLifecycle(lifecycleRepository),
            lifecycleRepository);

        var identities = await service.ListAsync(CancellationToken.None);

        Assert.That(identities.Select(identity => identity.Domain), Is.EqualTo(new[] { "newer.example", "older.example" }));
    }

    private static SigningKeyLifecycleService SigningKeyLifecycle()
    {
        var repository = new InMemorySigningKeyLifecycleRepository();
        return SigningKeyLifecycle(repository);
    }

    private static SigningKeyLifecycleService SigningKeyLifecycle(
        InMemorySigningKeyLifecycleRepository repository) =>
        new(
            repository,
            new AuditLogService(repository),
            new HipPublicKeyFingerprintService([new DevelopmentHipCryptoProvider()]));

    private static Task<SigningKeyRing> RegisterDefaultKeyAsync(
        ISigningKeyLifecycleService lifecycle,
        HipIdentity identity,
        HipKeyPair keyPair) =>
        lifecycle.RegisterAsync(
            new RegisterSigningKeyRequest(
                identity.IdentityId,
                HipIdentityService.InitialSigningKeyId,
                keyPair.Algorithm,
                keyPair.PublicKey,
                "test:identity-signing",
                "Register the test identity's managed signing key.",
                identity.CreatedAtUtc),
            CancellationToken.None);

    /// <summary>
    /// Test-only website identity repository used to verify service behavior without static process state.
    /// </summary>
    private sealed class TestWebsiteIdentityRepository : IWebsiteIdentityRepository
    {
        private readonly Dictionary<string, WebsiteIdentity> identities = new(StringComparer.OrdinalIgnoreCase);

        /// <inheritdoc />
        public Task<bool> TryCreateAsync(
            WebsiteIdentity websiteIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (identities)
            {
                return Task.FromResult(identities.TryAdd(websiteIdentity.Domain, websiteIdentity));
            }
        }

        public Task<bool> TryUpdateAsync(
            WebsiteIdentity expected,
            WebsiteIdentity updated,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (identities)
            {
                if (!identities.TryGetValue(expected.Domain, out var current) ||
                    !Equals(current, expected))
                {
                    return Task.FromResult(false);
                }

                identities[expected.Domain] = updated;
                return Task.FromResult(true);
            }
        }

        /// <summary>
        /// Saves a website identity for later test lookup.
        /// </summary>
        /// <param name="websiteIdentity">Website identity to save.</param>
        /// <param name="cancellationToken">Unused test cancellation token.</param>
        /// <returns>The saved website identity.</returns>
        public Task<WebsiteIdentity> SaveAsync(WebsiteIdentity websiteIdentity, CancellationToken cancellationToken)
        {
            identities[websiteIdentity.Domain] = websiteIdentity;
            return Task.FromResult(websiteIdentity);
        }

        /// <summary>
        /// Gets a saved website identity by domain.
        /// </summary>
        /// <param name="domain">Domain under test.</param>
        /// <param name="cancellationToken">Unused test cancellation token.</param>
        /// <returns>The saved identity, or null when none exists.</returns>
        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
        {
            identities.TryGetValue(domain, out var identity);
            return Task.FromResult(identity);
        }

        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyCollection<WebsiteIdentity>>(identities.Values.ToArray());
    }

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

