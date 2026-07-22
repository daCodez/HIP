using System.Collections.Concurrent;
using HIP.Application.Identity;
using HIP.Application.Protocol;
using HIP.Application.Review;
using HIP.Domain.Identity;

namespace HIP.Tests.Identity;

/// <summary>
/// Proves website-registration retries preserve the atomically elected identity key after later steps fail.
/// </summary>
public sealed class WebsiteIdentityRegistrationRecoveryTests
{
    [Test]
    public async Task Challenge_start_failure_preserves_the_elected_key_and_retry_does_not_reissue_it()
    {
        var domainVerification = new FaultingDomainVerificationService(failGetOrStartAttempts: 1);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 0);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "challenge-fault.example",
            "Challenge fault",
            VerificationMethod.WellKnownHipJson);

        var failure = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fixture.Service.RegisterAsync(request, CancellationToken.None));
        var identityAfterFailure = await fixture.Repository.GetRegisteredIdentityAsync(
            "hip:web:challenge-fault.example",
            CancellationToken.None);
        var ringAfterFailure = await fixture.Repository.GetAsync(
            "hip:web:challenge-fault.example",
            CancellationToken.None);

        var recovered = await fixture.Service.RegisterAsync(request, CancellationToken.None);
        var identityAfterRetry = await fixture.Repository.GetRegisteredIdentityAsync(
            "hip:web:challenge-fault.example",
            CancellationToken.None);
        var ringAfterRetry = await fixture.Repository.GetAsync(
            "hip:web:challenge-fault.example",
            CancellationToken.None);
        var audits = await fixture.AuditLogService.ListAsync(CancellationToken.None);
        var website = await websiteRepository.GetAsync("challenge-fault.example", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(failure!.Message, Is.EqualTo("Injected challenge start failure."));
            Assert.That(recovered.IsRecovery, Is.True);
            Assert.That(recovered.RequiresSigningKeyRotation, Is.True);
            Assert.That(recovered.DevelopmentPrivateKey, Is.Null);
            Assert.That(recovered.Warning, Does.Contain("did not retain or reissue"));
            Assert.That(identityAfterFailure, Is.Not.Null);
            Assert.That(ringAfterFailure, Is.Not.Null);
            Assert.That(identityAfterRetry, Is.EqualTo(identityAfterFailure));
            Assert.That(ringAfterRetry!.Version, Is.EqualTo(ringAfterFailure!.Version));
            Assert.That(
                ringAfterRetry.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKeyFingerprint,
                Is.EqualTo(ringAfterFailure.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKeyFingerprint));
            Assert.That(website, Is.EqualTo(recovered.WebsiteIdentity));
            Assert.That(domainVerification.GetOrStartCount, Is.EqualTo(2));
            Assert.That(RegistrationAudits(audits, "hip:web:challenge-fault.example"), Has.Length.EqualTo(1));
        });
    }

    [Test]
    public async Task Website_create_failure_preserves_the_elected_key_and_retry_starts_one_challenge()
    {
        var domainVerification = new FaultingDomainVerificationService(failGetOrStartAttempts: 0);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 1);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "website-save-fault.example",
            "Website save fault",
            VerificationMethod.DnsTxt);

        var failure = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fixture.Service.RegisterAsync(request, CancellationToken.None));
        var identityAfterFailure = await fixture.Repository.GetRegisteredIdentityAsync(
            "hip:web:website-save-fault.example",
            CancellationToken.None);
        var ringAfterFailure = await fixture.Repository.GetAsync(
            "hip:web:website-save-fault.example",
            CancellationToken.None);

        var recovered = await fixture.Service.RegisterAsync(request, CancellationToken.None);
        var identityAfterRetry = await fixture.Repository.GetRegisteredIdentityAsync(
            "hip:web:website-save-fault.example",
            CancellationToken.None);
        var ringAfterRetry = await fixture.Repository.GetAsync(
            "hip:web:website-save-fault.example",
            CancellationToken.None);
        var audits = await fixture.AuditLogService.ListAsync(CancellationToken.None);
        var website = await websiteRepository.GetAsync("website-save-fault.example", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(failure!.Message, Is.EqualTo("Injected website create failure."));
            Assert.That(recovered.IsRecovery, Is.True);
            Assert.That(recovered.DevelopmentPrivateKey, Is.Null);
            Assert.That(identityAfterFailure, Is.Not.Null);
            Assert.That(ringAfterFailure, Is.Not.Null);
            Assert.That(identityAfterRetry, Is.EqualTo(identityAfterFailure));
            Assert.That(ringAfterRetry!.Version, Is.EqualTo(ringAfterFailure!.Version));
            Assert.That(
                ringAfterRetry.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKeyFingerprint,
                Is.EqualTo(ringAfterFailure.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKeyFingerprint));
            Assert.That(website, Is.EqualTo(recovered.WebsiteIdentity));
            Assert.That(domainVerification.GetOrStartCount, Is.EqualTo(1));
            Assert.That(RegistrationAudits(audits, "hip:web:website-save-fault.example"), Has.Length.EqualTo(1));
        });
    }

    [Test]
    public async Task Concurrent_partial_registration_recovery_reuses_one_key_website_and_challenge()
    {
        var domainVerification = new FaultingDomainVerificationService(failGetOrStartAttempts: 0);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 1);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "concurrent-recovery.example",
            "Concurrent recovery",
            VerificationMethod.WellKnownHipJson);
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fixture.Service.RegisterAsync(request, CancellationToken.None));

        var attempts = Enumerable.Range(0, 8)
            .Select(async _ =>
            {
                try
                {
                    return (
                        Response: await fixture.Service.RegisterAsync(request, CancellationToken.None),
                        Error: (Exception?)null);
                }
                catch (Exception exception)
                {
                    return (
                        Response: (WebsiteIdentityRegistrationResponse?)null,
                        Error: exception);
                }
            })
            .ToArray();
        var outcomes = await Task.WhenAll(attempts);
        var recoveries = outcomes
            .Where(outcome => outcome.Response is not null)
            .Select(outcome => outcome.Response!)
            .ToArray();
        var errors = outcomes
            .Where(outcome => outcome.Error is not null)
            .Select(outcome => outcome.Error!)
            .ToArray();
        var website = await websiteRepository.GetAsync("concurrent-recovery.example", CancellationToken.None);
        var ring = await fixture.Repository.GetAsync(
            "hip:web:concurrent-recovery.example",
            CancellationToken.None);
        var audits = await fixture.AuditLogService.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(recoveries, Is.Not.Empty);
            Assert.That(errors, Has.All.TypeOf<WebsiteIdentityRegistrationConflictException>());
            Assert.That(recoveries, Has.All.Property(nameof(WebsiteIdentityRegistrationResponse.IsRecovery)).True);
            Assert.That(recoveries, Has.All.Property(nameof(WebsiteIdentityRegistrationResponse.DevelopmentPrivateKey)).Null);
            Assert.That(
                recoveries.Select(result => result.VerificationRequest.Token).Distinct().ToArray(),
                Has.Length.EqualTo(1));
            Assert.That(
                recoveries.Select(result => result.WebsiteIdentity).Distinct().ToArray(),
                Has.Length.EqualTo(1));
            Assert.That(website, Is.EqualTo(recoveries[0].WebsiteIdentity));
            Assert.That(
                website!.PublicKeys.Single().PublicKey,
                Is.EqualTo(ring!.GetRequiredKey(HipIdentityService.InitialSigningKeyId).PublicKey));
            Assert.That(RegistrationAudits(audits, "hip:web:concurrent-recovery.example"), Has.Length.EqualTo(1));
        });
    }

    [Test]
    public async Task Recovery_rejects_unmanaged_extra_website_keys()
    {
        var domainVerification = new FaultingDomainVerificationService(failGetOrStartAttempts: 0);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 0);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "extra-key.example",
            "Extra key",
            VerificationMethod.WellKnownHipJson);
        var registered = await fixture.Service.RegisterAsync(request, CancellationToken.None);
        await websiteRepository.SaveAsync(
            registered.WebsiteIdentity with
            {
                PublicKeys =
                [
                    .. registered.WebsiteIdentity.PublicKeys,
                    new SigningKey("unmanaged", "ML-DSA-65", "unmanaged-public-key")
                ]
            },
            CancellationToken.None);

        Assert.ThrowsAsync<WebsiteIdentityRegistrationConflictException>(() =>
            fixture.Service.RegisterAsync(request, CancellationToken.None));
    }

    [Test]
    public async Task Revocation_retry_reconciles_a_challenge_after_a_partial_failure()
    {
        var domainVerification = new FaultingDomainVerificationService(
            failGetOrStartAttempts: 0,
            failRevokeAttempts: 1);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 0);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "partial-revoke.example",
            "Partial revoke",
            VerificationMethod.WellKnownHipJson);
        var registered = await fixture.Service.RegisterAsync(request, CancellationToken.None);

        Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Service.RevokeVerificationAsync(
            registered.WebsiteIdentity.Domain,
            "Ownership withdrawn",
            "owner-1",
            "Owner",
            CancellationToken.None));
        Assert.ThrowsAsync<WebsiteIdentityRegistrationConflictException>(() =>
            fixture.Service.RegisterAsync(request, CancellationToken.None));
        var pendingWebsite = await websiteRepository.GetAsync(
            registered.WebsiteIdentity.Domain,
            CancellationToken.None);
        await websiteRepository.SaveAsync(
            pendingWebsite! with
            {
                VerificationStatus = VerificationStatus.Revoked,
                RevokedAtUtc = DateTimeOffset.UtcNow
            },
            CancellationToken.None);

        var reconciled = await fixture.Service.RevokeVerificationAsync(
            registered.WebsiteIdentity.Domain,
            "Ownership withdrawn",
            "owner-1",
            "Owner",
            CancellationToken.None);
        var challenge = await domainVerification.GetAsync(
            registered.WebsiteIdentity.Domain,
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);
        var revocationAudits = (await fixture.AuditLogService.ListAsync(CancellationToken.None))
            .Where(entry =>
                entry.Action == "domain-verification.revoked" &&
                entry.TargetId == registered.WebsiteIdentity.Domain)
            .ToArray();

        Assert.That(reconciled.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
        Assert.That(challenge!.Status, Is.EqualTo(VerificationStatus.Revoked));
        Assert.That(revocationAudits, Has.Length.EqualTo(1));
    }

    [Test]
    public async Task Concurrent_revocation_is_not_overwritten_by_stale_recovery_status()
    {
        var domainVerification = new FaultingDomainVerificationService(
            failGetOrStartAttempts: 0,
            pauseGetOrStart: true);
        var websiteRepository = new FaultingWebsiteIdentityRepository(failTryCreateAttempts: 1);
        var fixture = CreateFixture(domainVerification, websiteRepository);
        var request = new WebsiteIdentityRegistrationRequest(
            "revocation-race.example",
            "Revocation race",
            VerificationMethod.WellKnownHipJson);
        Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await fixture.Service.RegisterAsync(request, CancellationToken.None));
        domainVerification.Seed(new DomainVerificationRequest(
            "revocation-race.example",
            VerificationMethod.WellKnownHipJson,
            "existing-token",
            VerificationStatus.Verified,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow));

        var recoveryTask = fixture.Service.RegisterAsync(request, CancellationToken.None);
        await domainVerification.WaitUntilGetOrStartAsync();
        var pendingWebsite = await websiteRepository.GetAsync(
            "revocation-race.example",
            CancellationToken.None);
        await domainVerification.RevokeAsync(
            "revocation-race.example",
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);
        await websiteRepository.SaveAsync(
            pendingWebsite! with
            {
                VerificationStatus = VerificationStatus.Revoked,
                VerifiedAtUtc = null,
                RevokedAtUtc = DateTimeOffset.UtcNow
            },
            CancellationToken.None);
        domainVerification.ResumeGetOrStart();

        var recovered = await recoveryTask;
        var durableWebsite = await websiteRepository.GetAsync(
            "revocation-race.example",
            CancellationToken.None);
        var durableChallenge = await domainVerification.GetAsync(
            "revocation-race.example",
            VerificationMethod.WellKnownHipJson,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(recovered.WebsiteIdentity.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
            Assert.That(durableWebsite!.VerificationStatus, Is.EqualTo(VerificationStatus.Revoked));
            Assert.That(durableChallenge!.Status, Is.EqualTo(VerificationStatus.Revoked));
        });
    }

    private static RecoveryFixture CreateFixture(
        IDomainVerificationService domainVerificationService,
        IWebsiteIdentityRepository websiteIdentityRepository)
    {
        var cryptoProvider = new DevelopmentHipCryptoProvider();
        var repository = new InMemorySigningKeyLifecycleRepository();
        var auditLogService = new AuditLogService(repository);
        var lifecycleService = new SigningKeyLifecycleService(
            repository,
            auditLogService,
            new HipPublicKeyFingerprintService([cryptoProvider]));
        var service = new WebsiteIdentityService(
            cryptoProvider,
            repository,
            domainVerificationService,
            websiteIdentityRepository,
            auditLogService,
            lifecycleService,
            repository);
        return new RecoveryFixture(service, repository, auditLogService);
    }

    private static object[] RegistrationAudits(
        IReadOnlyCollection<HIP.Domain.Audit.AuditLogEntry> audits,
        string identityId) =>
        audits
            .Where(entry =>
                entry.Action == "IdentityAndSigningKeyRegistered" &&
                entry.Metadata.TryGetValue("identityId", out var auditedIdentityId) &&
                auditedIdentityId == identityId)
            .Cast<object>()
            .ToArray();

    private sealed record RecoveryFixture(
        WebsiteIdentityService Service,
        InMemorySigningKeyLifecycleRepository Repository,
        AuditLogService AuditLogService);

    /// <summary>Atomically reuses one challenge and can inject failures before it is created.</summary>
    private sealed class FaultingDomainVerificationService(
        int failGetOrStartAttempts,
        bool pauseGetOrStart = false,
        int failRevokeAttempts = 0) : IDomainVerificationService
    {
        private readonly ConcurrentDictionary<string, DomainVerificationRequest> requests =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly TaskCompletionSource<bool> getOrStartReached =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> resumeGetOrStart =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int failuresRemaining = failGetOrStartAttempts;
        private int revokeFailuresRemaining = failRevokeAttempts;
        private int getOrStartCount;

        public int GetOrStartCount => getOrStartCount;

        public Task<DomainVerificationRequest> StartAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) =>
            GetOrStartAsync(domain, method, cancellationToken);

        public async Task<DomainVerificationRequest> GetOrStartAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref getOrStartCount);
            if (Interlocked.Decrement(ref failuresRemaining) >= 0)
            {
                throw new InvalidOperationException("Injected challenge start failure.");
            }

            var request = requests.GetOrAdd(
                $"{method}:{domain}",
                _ => new DomainVerificationRequest(
                    domain,
                    method,
                    Guid.NewGuid().ToString("N"),
                    VerificationStatus.Pending,
                    DateTimeOffset.UtcNow,
                    null));
            if (pauseGetOrStart)
            {
                getOrStartReached.TrySetResult(true);
                await resumeGetOrStart.Task.WaitAsync(cancellationToken);
            }

            return request;
        }

        public void Seed(DomainVerificationRequest request) =>
            requests[$"{request.Method}:{request.Domain}"] = request;

        public Task WaitUntilGetOrStartAsync() => getOrStartReached.Task;

        public void ResumeGetOrStart() => resumeGetOrStart.TrySetResult(true);

        public Task<DomainVerificationRequest?> GetAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            requests.TryGetValue($"{method}:{domain}", out var request);
            return Task.FromResult(request);
        }

        public Task<DomainVerificationRequest> VerifyAsync(
            string domain,
            VerificationMethod method,
            string token,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainVerificationRetryResult> RetryAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainVerificationRequest> RevokeAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Decrement(ref revokeFailuresRemaining) >= 0)
            {
                throw new InvalidOperationException("Injected challenge revocation failure.");
            }
            if (!requests.TryGetValue($"{method}:{domain}", out var request))
            {
                throw new ArgumentException("Domain verification request was not found.", nameof(domain));
            }

            var revoked = request with
            {
                Status = VerificationStatus.Revoked,
                VerifiedAtUtc = null
            };
            requests[$"{method}:{domain}"] = revoked;
            return Task.FromResult(revoked);
        }

        public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(
            string domain,
            string expectedToken,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    /// <summary>Atomically creates website records or fails before mutating its dictionary.</summary>
    private sealed class FaultingWebsiteIdentityRepository(int failTryCreateAttempts) : IWebsiteIdentityRepository
    {
        private readonly ConcurrentDictionary<string, WebsiteIdentity> identities =
            new(StringComparer.OrdinalIgnoreCase);
        private int failuresRemaining = failTryCreateAttempts;

        public Task<bool> TryCreateAsync(
            WebsiteIdentity websiteIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Decrement(ref failuresRemaining) >= 0)
            {
                throw new InvalidOperationException("Injected website create failure.");
            }

            return Task.FromResult(identities.TryAdd(websiteIdentity.Domain, websiteIdentity));
        }

        public Task<bool> TryUpdateAsync(
            WebsiteIdentity expected,
            WebsiteIdentity updated,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!identities.TryGetValue(expected.Domain, out var current) ||
                !Equals(current, expected))
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(identities.TryUpdate(expected.Domain, updated, current));
        }

        public Task<WebsiteIdentity> SaveAsync(
            WebsiteIdentity websiteIdentity,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            identities[websiteIdentity.Domain] = websiteIdentity;
            return Task.FromResult(websiteIdentity);
        }

        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            identities.TryGetValue(domain, out var identity);
            return Task.FromResult(identity);
        }

        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyCollection<WebsiteIdentity>>(identities.Values.ToArray());
        }
    }
}
