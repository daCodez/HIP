using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Domain.Certificates;
using HIP.Domain.Domains;
using HIP.Domain.Identity;

namespace HIP.Tests.Domains;

public sealed class ManagedDomainCertificateApplicationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Unverified_domain_cannot_create_an_application()
    {
        var fixture = await Fixture.CreateAsync(verified: false);

        Assert.That(
            async () => await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Registered, default),
            Throws.TypeOf<InvalidOperationException>());
        Assert.That(await fixture.Repository.ListByDomainAsync(fixture.DomainId, default), Is.Empty);
    }

    [Test]
    public async Task Eligible_verified_application_is_approved_without_manual_review()
    {
        var fixture = await Fixture.CreateAsync();
        var draft = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Verified, default);

        var submitted = await fixture.Service.SubmitAsync("owner", draft.ApplicationId, default);

        Assert.Multiple(() =>
        {
            Assert.That(submitted.Status, Is.EqualTo(DomainCertificateApplicationStatus.Approved));
            Assert.That(submitted.SubmittedAtUtc, Is.EqualTo(Now));
            Assert.That(submitted.DecisionAtUtc, Is.EqualTo(Now));
            Assert.That(submitted.Eligibility?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
        });
    }

    [Test]
    public async Task Certified_application_with_strong_evidence_routes_to_review()
    {
        var fixture = await Fixture.CreateAsync();
        var draft = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Certified, default);

        var submitted = await fixture.Service.SubmitAsync("owner", draft.ApplicationId, default);

        Assert.Multiple(() =>
        {
            Assert.That(submitted.Status, Is.EqualTo(DomainCertificateApplicationStatus.PendingReview));
            Assert.That(submitted.Eligibility?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.RequiresReview));
            Assert.That(submitted.RequiredRemediation, Is.Empty);
        });
    }

    [Test]
    public async Task Authorized_reviewer_can_approve_a_pending_certified_application()
    {
        var fixture = await Fixture.CreateAsync();
        var draft = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Certified, default);
        var submitted = await fixture.Service.SubmitAsync("owner", draft.ApplicationId, default);

        var reviewed = await fixture.Service.ReviewAsync(
            "admin-reviewer", submitted.ApplicationId, approve: true, "Evidence independently confirmed.", default);

        Assert.Multiple(() =>
        {
            Assert.That(reviewed.Status, Is.EqualTo(DomainCertificateApplicationStatus.Approved));
            Assert.That(reviewed.ReviewerId, Is.EqualTo("admin-reviewer"));
            Assert.That(reviewed.ReviewerNotes, Is.EqualTo("Evidence independently confirmed."));
            Assert.That(reviewed.DecisionAtUtc, Is.EqualTo(Now));
            Assert.That(reviewed.Eligibility?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.RequiresReview));
        });
    }

    [Test]
    public async Task Review_decision_is_rejected_outside_pending_review()
    {
        var fixture = await Fixture.CreateAsync();
        var draft = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Registered, default);

        Assert.That(
            async () => await fixture.Service.ReviewAsync("admin-reviewer", draft.ApplicationId, true, null, default),
            Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public async Task Administrative_review_queue_returns_only_pending_applications()
    {
        var fixture = await Fixture.CreateAsync();
        var certified = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Certified, default);
        var registered = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Registered, default);
        await fixture.Service.SubmitAsync("owner", certified.ApplicationId, default);
        await fixture.Service.SubmitAsync("owner", registered.ApplicationId, default);

        var pending = await fixture.Service.ListPendingReviewAsync(default);

        Assert.That(pending.Select(item => item.ApplicationId), Is.EqualTo(new[] { certified.ApplicationId }));
    }

    [Test]
    public async Task Withdrawn_application_retains_its_record_and_cannot_be_resubmitted()
    {
        var fixture = await Fixture.CreateAsync();
        var draft = await fixture.Service.CreateDraftAsync("owner", fixture.DomainId, DomainCertificateLevel.Registered, default);
        var withdrawn = await fixture.Service.WithdrawAsync("owner", draft.ApplicationId, default);

        Assert.That(withdrawn.Status, Is.EqualTo(DomainCertificateApplicationStatus.Withdrawn));
        Assert.That(
            async () => await fixture.Service.SubmitAsync("owner", draft.ApplicationId, default),
            Throws.TypeOf<InvalidOperationException>());
        Assert.That(await fixture.Repository.ListByDomainAsync(fixture.DomainId, default), Has.Count.EqualTo(1));
    }

    private sealed record Fixture(
        string DomainId,
        ManagedDomainCertificateApplicationService Service,
        InMemoryManagedDomainCertificateApplicationRepository Repository)
    {
        public static async Task<Fixture> CreateAsync(bool verified = true)
        {
            var domains = new InMemoryManagedDomainRepository();
            var management = new DomainManagementService(
                domains,
                new DomainRegistrationNormalizer(new TestPublicSuffixResolver()),
                new FixedTimeProvider(Now));
            var domain = await management.RegisterAsync("owner", new("example.com"), default);
            if (verified)
            {
                await management.UpdateVerificationAsync(
                    "owner", domain.DomainId, ManagedDomainVerificationStatus.Verified,
                    VerificationMethod.DnsTxt, Now, default);
            }
            var repository = new InMemoryManagedDomainCertificateApplicationRepository();
            var evidence = new StubEvidenceSource(new DomainCertificateEvidenceSnapshot(
                AccountContactVerified: true,
                DomainControlVerifiedAtUtc: Now.AddHours(-1),
                DnsVerifiedAtUtc: Now.AddHours(-1),
                WebsiteVerifiedAtUtc: Now.AddHours(-1),
                InitialSecurityScanCompleted: true,
                IdentityInformationCompleted: true,
                HttpsAvailable: true,
                TlsCertificateValid: true,
                RequiredPoliciesPassed: true,
                CurrentTrustScore: 95,
                DnssecStatus: DomainDnssecStatus.Valid,
                OrganizationIdentityVerified: true));
            return new(domain.DomainId,
                new ManagedDomainCertificateApplicationService(
                    management, repository, evidence,
                    new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1),
                    new FixedTimeProvider(Now)), repository);
        }
    }

    private sealed class StubEvidenceSource(DomainCertificateEvidenceSnapshot evidence)
        : IManagedDomainCertificationEvidenceSource
    {
        public Task<ManagedDomainCertificationEvidence> GetAsync(string domainId, string domainName, CancellationToken cancellationToken) =>
            Task.FromResult(new ManagedDomainCertificationEvidence(evidence, new DomainCertificateReviewSignals()));
    }
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver { public string? RegistrableDomain(string canonicalDomain) => canonicalDomain; }
}
