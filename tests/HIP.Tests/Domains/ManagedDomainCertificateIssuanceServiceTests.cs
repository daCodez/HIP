using HIP.Application.Certificates;
using HIP.Application.Domains;
using HIP.Domain.Certificates;
using HIP.Domain.Domains;
using HIP.Domain.Identity;

namespace HIP.Tests.Domains;

public sealed class ManagedDomainCertificateIssuanceServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Approved_application_issues_with_stable_domain_links_and_snapshot()
    {
        var fixture = await Fixture.CreateAsync(DomainCertificateLevel.Verified, DomainCertificatePolicyDecision.Eligible, reviewed: false);

        var result = await fixture.Service.IssueAsync("owner", fixture.ApplicationId, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(ManagedDomainCertificateIssuanceStatus.Issued));
            Assert.That(result.PublicCertificateNumber, Does.Match("^HIP-2026-[A-F0-9]{24}$"));
            Assert.That(fixture.Issuance.Request?.ManagedDomainId, Is.EqualTo(fixture.DomainId));
            Assert.That(fixture.Issuance.Request?.ApplicationId, Is.EqualTo(fixture.ApplicationId));
            Assert.That(fixture.Issuance.Request?.PublicCertificateNumber, Is.EqualTo(result.PublicCertificateNumber));
            Assert.That(fixture.Issuance.Request?.Snapshot?.HipScore, Is.EqualTo(95));
            Assert.That(fixture.Issuance.Request?.Snapshot?.DnssecStatus, Is.EqualTo(DomainDnssecStatus.Valid));
            Assert.That(fixture.Issuance.Request?.Draft.AuthorizedReview, Is.Null);
        });
    }

    [Test]
    public async Task Reviewed_certified_application_carries_authorized_review_into_signing()
    {
        var fixture = await Fixture.CreateAsync(DomainCertificateLevel.Certified, DomainCertificatePolicyDecision.RequiresReview, reviewed: true);

        var result = await fixture.Service.IssueAsync("owner", fixture.ApplicationId, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(ManagedDomainCertificateIssuanceStatus.Issued));
            Assert.That(fixture.Issuance.Request?.Draft.AuthorizedReview?.ReviewerId, Is.EqualTo("reviewer"));
            Assert.That(fixture.Issuance.Request?.Draft.AuthorizedReview?.ApplicationId, Is.EqualTo(fixture.ApplicationId));
        });
    }

    [Test]
    public async Task Review_required_evidence_without_authorized_review_is_not_issued()
    {
        var fixture = await Fixture.CreateAsync(DomainCertificateLevel.Certified, DomainCertificatePolicyDecision.RequiresReview, reviewed: false);

        var result = await fixture.Service.IssueAsync("owner", fixture.ApplicationId, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(ManagedDomainCertificateIssuanceStatus.ReviewRequired));
            Assert.That(fixture.Issuance.Request, Is.Null);
        });
    }

    [Test]
    public void Public_certificate_number_is_stable_and_does_not_expose_application_id()
    {
        var generator = new OpaquePublicCertificateNumberGenerator();

        var first = generator.Create("domain-application_0123456789abcdef", Now);
        var second = generator.Create("domain-application_0123456789abcdef", Now.AddDays(1));

        Assert.Multiple(() =>
        {
            Assert.That(second, Is.EqualTo(first));
            Assert.That(first, Does.Not.Contain("0123456789abcdef"));
        });
    }

    private sealed record Fixture(
        string DomainId,
        string ApplicationId,
        ManagedDomainCertificateIssuanceService Service,
        RecordingIssuanceService Issuance)
    {
        public static async Task<Fixture> CreateAsync(
            DomainCertificateLevel level,
            DomainCertificatePolicyDecision decision,
            bool reviewed)
        {
            var domains = new InMemoryManagedDomainRepository();
            var management = new DomainManagementService(
                domains, new DomainRegistrationNormalizer(new TestPublicSuffixResolver()), new FixedTimeProvider(Now));
            var domain = await management.RegisterAsync("owner", new("example.com"), default);
            await management.UpdateVerificationAsync(
                "owner", domain.DomainId, ManagedDomainVerificationStatus.Verified,
                VerificationMethod.DnsTxt, Now.AddHours(-2), default);

            var evidence = Evidence();
            var evidenceSource = new StubEvidenceSource(evidence);
            var applicationRepository = new InMemoryManagedDomainCertificateApplicationRepository();
            var applicationId = "domain-application_0123456789abcdef";
            var evaluation = Evaluation(level, decision);
            await applicationRepository.AddAsync(new ManagedDomainCertificateApplication(
                applicationId, domain.DomainId, domain.DomainName, level, "owner", null,
                DomainCertificateApplicationStatus.Approved, Now.AddDays(-1), Now.AddHours(-2), evaluation,
                [], [], reviewed ? "reviewer" : null, reviewed ? "Confirmed." : null,
                reviewed ? "Approved after authorized manual review." : "Automatically approved by versioned eligibility policy.",
                reviewed ? Now.AddHours(-1) : Now.AddHours(-2), 2), default);
            var applications = new ManagedDomainCertificateApplicationService(
                management, applicationRepository, evidenceSource,
                new FixedEvaluator(evaluation), new FixedTimeProvider(Now));
            var issuance = new RecordingIssuanceService();
            var service = new ManagedDomainCertificateIssuanceService(
                management, applications, evidenceSource, new FixedEvaluator(evaluation),
                new EnrollmentRepository(), issuance, new OpaquePublicCertificateNumberGenerator(),
                DomainCertificatePublicEndpointOptions.Default, new FixedTimeProvider(Now));
            return new(domain.DomainId, applicationId, service, issuance);
        }
    }

    private static DomainCertificateEvidenceSnapshot Evidence() => new(
        AccountContactVerified: true,
        DomainControlVerifiedAtUtc: Now.AddHours(-3),
        DnsVerifiedAtUtc: Now.AddHours(-3),
        WebsiteVerifiedAtUtc: Now.AddHours(-2),
        InitialSecurityScanCompleted: true,
        IdentityInformationCompleted: true,
        HttpsAvailable: true,
        TlsCertificateValid: true,
        RequiredPoliciesPassed: true,
        CurrentTrustScore: 95,
        DnssecStatus: DomainDnssecStatus.Valid,
        OrganizationIdentityVerified: true,
        DomainTrustScore: 94,
        PageTrustScore: 96,
        ContentRiskScore: 97,
        ScanId: "scan-123");

    private static DomainCertificatePolicyEvaluationResult Evaluation(
        DomainCertificateLevel level,
        DomainCertificatePolicyDecision decision) => new(
            "example.com", level, DomainCertificatePolicy.V1.Version, decision,
            "Public meaning.", [], Now.AddMinutes(-10));

    private sealed class FixedEvaluator(DomainCertificatePolicyEvaluationResult result) : IDomainCertificatePolicyEvaluator
    {
        public DomainCertificatePolicyEvaluationResult Evaluate(DomainCertificatePolicyEvaluationRequest request) =>
            result with { EvaluatedAtUtc = request.EvaluatedAtUtc };
    }

    private sealed class StubEvidenceSource(DomainCertificateEvidenceSnapshot evidence) : IManagedDomainCertificationEvidenceSource
    {
        public Task<ManagedDomainCertificationEvidence> GetAsync(string domainId, string domainName, CancellationToken cancellationToken) =>
            Task.FromResult(new ManagedDomainCertificationEvidence(evidence, new DomainCertificateReviewSignals()));
    }

    private sealed class EnrollmentRepository : IDomainEnrollmentRepository
    {
        public Task<DomainEnrollmentStateRecord?> GetCurrentAsync(string ownerId, string domain, CancellationToken cancellationToken) =>
            Task.FromResult<DomainEnrollmentStateRecord?>(new(
                "enrollment-1", ownerId, domain, DomainEnrollmentStatus.Verified,
                Now.AddHours(-3), Now.AddHours(-2), Now.AddHours(-2), "Example", "Example Org"));
        public Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(DomainEnrollmentStartRecord enrollment, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(DomainOwnershipVerificationRecord verification, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(DomainWebsiteVerificationRecord verification, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(DomainCertificateIdentityProfileRecord profile, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(DomainCertificateSecurityReviewRecord review, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingIssuanceService : IDomainCertificateIssuanceService
    {
        public DomainCertificateIssuanceRequest? Request { get; private set; }
        public Task<DomainCertificateIssuanceResult> IssueAsync(DomainCertificateIssuanceRequest request, CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new DomainCertificateIssuanceResult(DomainCertificateIssuanceStatus.Issued));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private sealed class TestPublicSuffixResolver : IPublicSuffixResolver { public string? RegistrableDomain(string canonicalDomain) => canonicalDomain; }
}
