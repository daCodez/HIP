using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Application.SiteSafety;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateProvisioningServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 26, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Eligible_server_review_is_persisted_before_signed_issuance()
    {
        var enrollment = new DomainEnrollmentStateRecord(
            "enrollment-1",
            "owner-1",
            "example.com",
            DomainEnrollmentStatus.PendingSecurityReview,
            Now.AddHours(-2),
            Now.AddHours(-1),
            Now.AddMinutes(-30),
            "Example Site",
            "Example Org");
        var repository = new RecordingEnrollmentRepository(enrollment);
        var evaluation = new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1).Evaluate(
            new DomainCertificatePolicyEvaluationRequest(
                "example.com",
                DomainCertificateLevel.Verified,
                new DomainCertificateEvidenceSnapshot(
                    true, Now.AddHours(-2), Now.AddHours(-2), Now.AddHours(-1),
                    true, 0, true, true, true, true),
                new DomainCertificateReviewSignals(),
                Now));
        var scan = new FixedSecurityScanService(new DomainCertificateSecurityScanResult(
            DomainCertificateSecurityScanStatus.Evaluated,
            Scan(),
            evaluation,
            DomainCertificatePublicRiskClassification.Low,
            []));
        var issuance = new RecordingIssuanceService();
        var service = new DomainCertificateProvisioningService(
            repository,
            scan,
            issuance,
            new Rfc8785CanonicalJsonService(),
            DomainCertificatePublicEndpointOptions.Default);

        var result = await service.ReviewAndIssueAsync(
            "owner-1",
            "example.com",
            accountContactVerified: true,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateProvisioningStatus.Issued));
            Assert.That(repository.Review, Is.Not.Null);
            Assert.That(repository.Review!.EvidenceDigest, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(repository.Review.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
            Assert.That(issuance.Request, Is.Not.Null);
            Assert.That(issuance.Request!.Draft.PublicDisplayName, Is.EqualTo("Example Site"));
            Assert.That(issuance.Request.Draft.PublicOrganizationName, Is.EqualTo("Example Org"));
            Assert.That(issuance.Request.Draft.CompletedVerificationMethods, Has.Count.EqualTo(2));
            Assert.That(issuance.Request.Draft.RevocationStatusUrl,
                Does.StartWith("https://hiptrust.com/api/v1/certificates/"));
        });
    }

    private static SiteSafetyScanResult Scan() =>
        new(
            "scan-1",
            "https://example.com/",
            "example.com",
            Now,
            0, 0, 0, 0, 0, 0, 0, 0,
            SiteSafetyScanStatus.Clean,
            "Clean server-owned scan.",
            ["No critical signals."],
            [], [], [],
            "High",
            85, 85, 90, 86,
            [],
            new SiteSafetyScoreImpact(85, 85, 90, 86, []));

    private sealed class RecordingEnrollmentRepository(DomainEnrollmentStateRecord enrollment)
        : IDomainEnrollmentRepository
    {
        public DomainCertificateSecurityReviewRecord? Review { get; private set; }

        public Task<DomainEnrollmentStateRecord?> GetCurrentAsync(
            string ownerId,
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainEnrollmentStateRecord?>(
                ownerId == enrollment.OwnerId && domain == enrollment.Domain ? enrollment : null);

        public Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(
            DomainCertificateSecurityReviewRecord review,
            CancellationToken cancellationToken)
        {
            Review = review;
            return Task.FromResult(new DomainEnrollmentTransitionWriteResult(
                DomainEnrollmentTransitionWriteStatus.Updated));
        }

        public Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
            DomainEnrollmentStartRecord enrollment,
            CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
            DomainOwnershipVerificationRecord verification,
            CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(
            DomainWebsiteVerificationRecord verification,
            CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(
            DomainCertificateIdentityProfileRecord profile,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FixedSecurityScanService(DomainCertificateSecurityScanResult result)
        : IDomainCertificateSecurityScanService
    {
        public Task<DomainCertificateSecurityScanResult> ScanAsync(
            DomainCertificateSecurityScanRequest request,
            CancellationToken cancellationToken) => Task.FromResult(result);
    }

    private sealed class RecordingIssuanceService : IDomainCertificateIssuanceService
    {
        public DomainCertificateIssuanceRequest? Request { get; private set; }

        public Task<DomainCertificateIssuanceResult> IssueAsync(
            DomainCertificateIssuanceRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new DomainCertificateIssuanceResult(
                DomainCertificateIssuanceStatus.Issued));
        }
    }
}
