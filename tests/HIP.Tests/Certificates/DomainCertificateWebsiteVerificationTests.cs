using HIP.Application.Certificates;
using HIP.Application.Identity;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateWebsiteVerificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Enrollment_start_keeps_consumer_scope_separate_from_the_authenticated_domain_actor()
    {
        const string domain = "example.com";
        const string owner = "local-account-owner";
        const string domainActor = "hip-dev-admin";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "dns-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "unused", owner, domain, DomainEnrollmentStatus.PendingOwnership, Now, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge);
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(requests),
            requests,
            new StubFetcher(),
            websiteIdentities);

        var result = await service.StartAsync(
            owner,
            domainActor,
            new DomainCertificateEnrollmentStartRequest(
                domain,
                "Example",
                VerificationMethod.DnsTxt),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateEnrollmentStartStatus.Started));
            Assert.That(websiteIdentities.LastActorId, Is.EqualTo(domainActor));
            Assert.That(enrollments.StartedEnrollment?.OwnerId, Is.EqualTo(owner));
            Assert.That(enrollments.StartedEnrollment?.Domain, Is.EqualTo(domain));
        });
    }

    [Test]
    public async Task Development_enrollment_recovers_a_legacy_local_owner_claim_for_the_same_authenticated_session()
    {
        const string domain = "example.com";
        const string owner = "local-account-owner";
        const string domainActor = "hip-dev-admin";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "dns-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "unused", owner, domain, DomainEnrollmentStatus.PendingOwnership, Now, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge)
        {
            RequiredActorId = "system:legacy-website-registration"
        };
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(requests),
            requests,
            new StubFetcher(),
            websiteIdentities,
            DomainCertificateEnrollmentOwnershipPolicy.Development);

        var result = await service.StartAsync(
            owner,
            domainActor,
            new DomainCertificateEnrollmentStartRequest(domain, "Example", VerificationMethod.DnsTxt),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateEnrollmentStartStatus.Started));
            Assert.That(
                websiteIdentities.ActorIds,
                Is.EqualTo(new[] { domainActor, "system:legacy-website-registration" }));
        });
    }

    [Test]
    public async Task Production_enrollment_does_not_accept_the_legacy_local_owner_alias()
    {
        const string domain = "example.com";
        const string owner = "local-account-owner";
        const string domainActor = "hip-dev-admin";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "dns-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "unused", owner, domain, DomainEnrollmentStatus.PendingOwnership, Now, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge)
        {
            RequiredActorId = "system:legacy-website-registration"
        };
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(requests),
            requests,
            new StubFetcher(),
            websiteIdentities,
            DomainCertificateEnrollmentOwnershipPolicy.Default);

        var result = await service.StartAsync(
            owner,
            domainActor,
            new DomainCertificateEnrollmentStartRequest(domain, "Example", VerificationMethod.DnsTxt),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateEnrollmentStartStatus.Conflict));
            Assert.That(websiteIdentities.ActorIds, Is.EqualTo(new[] { domainActor }));
            Assert.That(enrollments.StartedEnrollment, Is.Null);
        });
    }

    [Test]
    public async Task Enrollment_start_fails_closed_when_production_identity_key_custody_is_unavailable()
    {
        const string domain = "example.com";
        const string owner = "owner-1";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "unused", owner, domain, DomainEnrollmentStatus.PendingOwnership, Now, null));
        var requests = new StubVerificationRequests(new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "unused", VerificationStatus.Pending,
            Now, null, Now.AddHours(1)));
        var websiteIdentities = new StubWebsiteIdentityService(website)
        {
            RegistrationUnavailable = true
        };
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(requests),
            requests,
            new StubFetcher(),
            websiteIdentities);

        var result = await service.StartAsync(
            owner,
            owner,
            new DomainCertificateEnrollmentStartRequest(domain, "Example", VerificationMethod.DnsTxt),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateEnrollmentStartStatus.IdentityKeyUnavailable));
            Assert.That(enrollments.StartedEnrollment, Is.Null);
        });
    }

    [Test]
    public async Task Existing_owner_can_recover_the_current_dns_challenge_without_starting_again()
    {
        const string domain = "example.com";
        const string owner = "owner-1";
        const string domainActor = "domain-owner";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "current-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "enrollment-1", owner, domain, DomainEnrollmentStatus.PendingOwnership, null, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge);
        var service = CreateService(
            website, enrollments, new StubDomainVerificationService(requests), requests, new StubFetcher(),
            websiteIdentities);

        var result = await service.GetCurrentDnsChallengeAsync(
            owner, domainActor, domain, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateDnsChallengeStatus.Available));
            Assert.That(result.Domain, Is.EqualTo(domain));
            Assert.That(result.ChallengeToken, Is.EqualTo(challenge.Token));
            Assert.That(result.ChallengeExpiresAtUtc, Is.EqualTo(challenge.ExpiresAtUtc));
            Assert.That(websiteIdentities.LastActorId, Is.EqualTo(domainActor));
            Assert.That(enrollments.StartedEnrollment, Is.Null);
        });
    }

    [Test]
    public async Task Development_owner_can_recover_a_legacy_challenge_when_account_and_actor_ids_match()
    {
        const string domain = "example.com";
        const string owner = "local-account-owner";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "current-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "enrollment-1", owner, domain, DomainEnrollmentStatus.PendingOwnership, null, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge)
        {
            RequiredActorId = "system:legacy-website-registration"
        };
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(requests),
            requests,
            new StubFetcher(),
            websiteIdentities,
            DomainCertificateEnrollmentOwnershipPolicy.Development);

        var result = await service.GetCurrentDnsChallengeAsync(
            owner, owner, domain, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateDnsChallengeStatus.Available));
            Assert.That(result.ChallengeToken, Is.EqualTo(challenge.Token));
            Assert.That(
                websiteIdentities.ActorIds,
                Is.EqualTo(new[] { owner, "system:legacy-website-registration" }));
        });
    }
    [Test]
    public async Task Current_dns_challenge_is_not_disclosed_to_a_different_account()
    {
        const string domain = "example.com";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Pending,
            VerificationMethod.DnsTxt, Now, null);
        var challenge = new DomainVerificationRequest(
            domain, VerificationMethod.DnsTxt, "current-challenge", VerificationStatus.Pending,
            Now, null, Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "enrollment-1", "owner-1", domain, DomainEnrollmentStatus.PendingOwnership, null, null));
        var requests = new StubVerificationRequests(challenge);
        var websiteIdentities = new StubWebsiteIdentityService(website, challenge);
        var service = CreateService(
            website, enrollments, new StubDomainVerificationService(requests), requests, new StubFetcher(),
            websiteIdentities);

        var result = await service.GetCurrentDnsChallengeAsync(
            "owner-2", "other-domain-actor", domain, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateDnsChallengeStatus.NotFound));
            Assert.That(result.ChallengeToken, Is.Null);
            Assert.That(websiteIdentities.ActorIds, Is.Empty);
            Assert.That(enrollments.StartedEnrollment, Is.Null);
        });
    }

    [Test]
    public async Task Prepare_and_check_use_an_owner_bound_single_use_https_challenge()
    {
        const string domain = "example.com";
        const string owner = "owner-1";
        var key = new SigningKey("key-1", "test", "public-key");
        var website = new WebsiteIdentity(
            domain,
            "hip:web:example.com",
            [key],
            VerificationStatus.Verified,
            VerificationMethod.DnsTxt,
            Now.AddDays(-1),
            Now.AddHours(-1));
        var challenge = new DomainVerificationRequest(
            domain,
            VerificationMethod.WellKnownHipJson,
            "secret-challenge",
            VerificationStatus.Pending,
            Now,
            null,
            Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(
            new DomainEnrollmentStateRecord(
                "enrollment-1",
                owner,
                domain,
                DomainEnrollmentStatus.OwnershipVerified,
                Now.AddHours(-1),
                null));
        var challenges = new StubVerificationRequests(challenge);
        var verification = new StubDomainVerificationService(challenges);
        var fetcher = new StubFetcher();
        var service = CreateService(website, enrollments, verification, challenges, fetcher);

        var prepared = await service.PrepareWebsiteVerificationAsync(owner, domain, CancellationToken.None);
        fetcher.Document = prepared.Document;
        var checkedResult = await service.CheckWebsiteAsync(owner, domain, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(prepared.Status, Is.EqualTo(DomainCertificateWebsitePrepareStatus.Ready));
            Assert.That(prepared.Document?.Signature, Is.Null);
            Assert.That(prepared.Document?.VerificationChallenge, Is.EqualTo(challenge.Token));
            Assert.That(checkedResult.Status, Is.EqualTo(DomainCertificateWebsiteCheckStatus.Verified));
            Assert.That(challenges.Current.Status, Is.EqualTo(VerificationStatus.Verified));
            Assert.That(challenges.Current.ConsumedAtUtc, Is.EqualTo(Now));
            Assert.That(enrollments.AppliedWebsiteVerification?.Method, Is.EqualTo(VerificationMethod.WellKnownHipJson));
            Assert.That(enrollments.AppliedWebsiteVerification?.OwnerId, Is.EqualTo(owner));
        });
    }

    [Test]
    public async Task Mismatched_https_challenge_remains_pending_without_consuming_or_advancing()
    {
        const string domain = "example.com";
        const string owner = "owner-1";
        var key = new SigningKey("key-1", "test", "public-key");
        var website = new WebsiteIdentity(
            domain,
            "hip:web:example.com",
            [key],
            VerificationStatus.Verified,
            VerificationMethod.DnsTxt,
            Now.AddDays(-1),
            Now.AddHours(-1));
        var challenge = new DomainVerificationRequest(
            domain,
            VerificationMethod.WellKnownHipJson,
            "expected",
            VerificationStatus.Pending,
            Now,
            null,
            Now.AddHours(1));
        var enrollments = new StubEnrollmentRepository(
            new DomainEnrollmentStateRecord(
                "enrollment-1",
                owner,
                domain,
                DomainEnrollmentStatus.OwnershipVerified,
                Now.AddHours(-1),
                null));
        var challenges = new StubVerificationRequests(challenge);
        var fetcher = new StubFetcher
        {
            Document = new HipWellKnownDocument(
                domain,
                website.HipIdentityId,
                website.PublicKeys,
                Now,
                VerificationChallenge: "attacker-value",
                ExpiresAtUtc: Now.AddMinutes(30))
        };
        var service = CreateService(
            website,
            enrollments,
            new StubDomainVerificationService(challenges),
            challenges,
            fetcher);

        var result = await service.CheckWebsiteAsync(owner, domain, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateWebsiteCheckStatus.Pending));
            Assert.That(challenges.Current.Status, Is.EqualTo(VerificationStatus.Unverified));
            Assert.That(challenges.Current.VerificationAttemptCount, Is.EqualTo(1));
            Assert.That(challenges.Current.LastAttemptOutcome, Is.EqualTo(DomainVerificationAttemptOutcome.Failed));
            Assert.That(challenges.Current.LastCheckMessage, Does.Not.Contain(challenge.Token));
            Assert.That(enrollments.AppliedWebsiteVerification, Is.Null);
        });
    }

    [Test]
    public async Task Identity_profile_hashes_private_contact_and_omits_unpublished_fields()
    {
        const string domain = "example.com";
        const string owner = "owner-1";
        var website = new WebsiteIdentity(
            domain, "hip:web:example.com", [], VerificationStatus.Verified,
            VerificationMethod.DnsTxt, Now.AddDays(-1), Now.AddHours(-1));
        var enrollments = new StubEnrollmentRepository(new DomainEnrollmentStateRecord(
            "enrollment-1", owner, domain, DomainEnrollmentStatus.PendingSecurityReview,
            Now.AddHours(-2), Now.AddHours(-1)));
        var challenges = new StubVerificationRequests(new DomainVerificationRequest(
            domain, VerificationMethod.WellKnownHipJson, "used", VerificationStatus.Verified,
            Now.AddHours(-1), Now.AddHours(-1), Now.AddHours(1)));
        var service = CreateService(website, enrollments, new StubDomainVerificationService(challenges), challenges, new StubFetcher());

        var result = await service.CompleteIdentityProfileAsync(
            owner, domain,
            new DomainCertificateIdentityProfileRequest(
                "Example", "Private Org", "https://example.com/contact", "Security@Example.com", "CA",
                PublishOrganization: false, PublishCountryOrRegion: false),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateIdentityProfileStatus.Completed));
            Assert.That(enrollments.AppliedIdentityProfile?.PublicDisplayName, Is.EqualTo("Example"));
            Assert.That(enrollments.AppliedIdentityProfile?.PublicOrganizationName, Is.Null);
            Assert.That(enrollments.AppliedIdentityProfile?.PublicCountryOrRegion, Is.Null);
            Assert.That(enrollments.AppliedIdentityProfile?.PublicWebsiteContact, Is.EqualTo("https://example.com/contact"));
            Assert.That(enrollments.AppliedIdentityProfile?.SecurityContactHash, Does.StartWith("sha256:"));
            Assert.That(enrollments.AppliedIdentityProfile?.SecurityContactHash, Does.Not.Contain("Security@Example.com"));
        });
    }

    private static DomainCertificateEnrollmentService CreateService(
        WebsiteIdentity website,
        StubEnrollmentRepository enrollments,
        StubDomainVerificationService verification,
        StubVerificationRequests requests,
        StubFetcher fetcher,
        StubWebsiteIdentityService? websiteIdentities = null,
        DomainCertificateEnrollmentOwnershipPolicy? ownershipPolicy = null) =>
        new(
            new DomainRegistrationNormalizer(new TestPublicSuffixResolver()),
            websiteIdentities ?? new StubWebsiteIdentityService(website),
            enrollments,
            verification,
            requests,
            fetcher,
            DomainCertificatePolicy.V1,
            new FixedTimeProvider(Now),
            ownershipPolicy: ownershipPolicy);

    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver
    {
        public string? RegistrableDomain(string canonicalDomain) => canonicalDomain;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class StubFetcher : IWellKnownHipDocumentFetcher
    {
        public HipWellKnownDocument? Document { get; set; }

        public Task<HipWellKnownDocument?> FetchAsync(string normalizedDomain, CancellationToken cancellationToken) =>
            Task.FromResult(Document);
    }

    private sealed class StubEnrollmentRepository(DomainEnrollmentStateRecord current)
        : IDomainEnrollmentRepository
    {
        public DomainWebsiteVerificationRecord? AppliedWebsiteVerification { get; private set; }
        public DomainCertificateIdentityProfileRecord? AppliedIdentityProfile { get; private set; }
        public DomainEnrollmentStartRecord? StartedEnrollment { get; private set; }

        public Task<DomainEnrollmentStateRecord?> GetCurrentAsync(
            string ownerId,
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainEnrollmentStateRecord?>(
                current.OwnerId == ownerId && current.Domain == domain ? current : null);

        public Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(
            DomainWebsiteVerificationRecord verification,
            CancellationToken cancellationToken)
        {
            AppliedWebsiteVerification = verification;
            return Task.FromResult(new DomainEnrollmentTransitionWriteResult(
                DomainEnrollmentTransitionWriteStatus.Updated));
        }

        public Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
            DomainEnrollmentStartRecord enrollment,
            CancellationToken cancellationToken)
        {
            StartedEnrollment = enrollment;
            return Task.FromResult(new DomainEnrollmentRepositoryWriteResult(
                DomainEnrollmentRepositoryWriteStatus.Created,
                enrollment));
        }

        public Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
            DomainOwnershipVerificationRecord verification,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(
            DomainCertificateIdentityProfileRecord profile,
            CancellationToken cancellationToken)
        {
            AppliedIdentityProfile = profile;
            return Task.FromResult(new DomainEnrollmentTransitionWriteResult(
                DomainEnrollmentTransitionWriteStatus.Updated));
        }

        public Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(
            DomainCertificateSecurityReviewRecord review,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class StubVerificationRequests(DomainVerificationRequest request)
        : IDomainVerificationRequestRepository
    {
        public DomainVerificationRequest Current { get; private set; } = request;

        public Task<bool> TryCreateAsync(DomainVerificationRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<bool> TryUpdateAsync(
            DomainVerificationRequest expected,
            DomainVerificationRequest updated,
            CancellationToken cancellationToken)
        {
            if (Current != expected)
            {
                return Task.FromResult(false);
            }

            Current = updated;
            return Task.FromResult(true);
        }

        public Task<DomainVerificationRequest> SaveAsync(
            DomainVerificationRequest request,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DomainVerificationRequest?> GetAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainVerificationRequest?>(Current);
    }

    private sealed class StubDomainVerificationService(StubVerificationRequests requests)
        : IDomainVerificationService
    {
        public Task<DomainVerificationRequest> GetOrStartAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) => Task.FromResult(requests.Current);

        public Task<DomainVerificationRequest?> GetAsync(
            string domain,
            VerificationMethod method,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainVerificationRequest?>(requests.Current);

        public Task<DomainVerificationRequest> StartAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<DomainVerificationRequest> VerifyAsync(string domain, VerificationMethod method, string token, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<DomainVerificationRetryResult> RetryAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<DomainVerificationRequest> RevokeAsync(string domain, VerificationMethod method, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<DomainVerificationCheckResult> CheckDnsTxtAsync(string domain, string expectedToken, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class StubWebsiteIdentityService(
        WebsiteIdentity website,
        DomainVerificationRequest? registrationChallenge = null) : IWebsiteIdentityService
    {
        public string? LastActorId { get; private set; }
        public List<string> ActorIds { get; } = [];
        public string? RequiredActorId { get; init; }
        public bool RegistrationUnavailable { get; init; }

        public Task<WebsiteIdentity?> GetAsync(
            string domain,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken)
        {
            LastActorId = actorId;
            ActorIds.Add(actorId);
            EnsureActor(actorId);
            return Task.FromResult<WebsiteIdentity?>(website.Domain == domain ? website : null);
        }

        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(WebsiteIdentityRegistrationRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<WebsiteIdentityRegistrationResponse> RegisterAsync(
            WebsiteIdentityRegistrationRequest request,
            string actorId,
            string actorRole,
            CancellationToken cancellationToken)
        {
            LastActorId = actorId;
            ActorIds.Add(actorId);
            EnsureActor(actorId);
            if (RegistrationUnavailable)
            {
                throw new PlatformNotSupportedException("Test managed key custody is unavailable.");
            }

            return Task.FromResult(new WebsiteIdentityRegistrationResponse(
                website,
                registrationChallenge ?? throw new InvalidOperationException("A registration challenge was not configured."),
                DevelopmentPrivateKey: null,
                Warning: "Test registration recovery.",
                IsRecovery: true,
                RequiresSigningKeyRotation: false));
        }

        private void EnsureActor(string actorId)
        {
            if (RequiredActorId is not null &&
                !string.Equals(actorId, RequiredActorId, StringComparison.Ordinal))
            {
                throw new WebsiteIdentityRegistrationConflictException("Test owner mismatch.");
            }
        }

        public Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> VerifyAsync(WebsiteVerificationRequest request, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity?> GetAsync(string domain, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyCollection<WebsiteIdentity>> ListAsync(string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> RetryVerificationAsync(string domain, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentityRegistrationResponse> RenewExpiredVerificationAsync(string domain, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<WebsiteIdentity> RevokeVerificationAsync(string domain, string reason, string actorId, string actorRole, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<HipWellKnownDocument> BuildWellKnownDocumentAsync(string domain, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
