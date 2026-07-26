using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateApplicationServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 26, 15, 30, 0, TimeSpan.Zero);

    [Test]
    public async Task Authenticated_declarations_create_digest_bound_submission()
    {
        var repository = new ApplicationRepository(ReadyEnrollment());
        var service = new DomainCertificateApplicationService(repository, new FixedTimeProvider(Now));

        var result = await service.SubmitAsync(
            "owner-1",
            "example.com",
            authorityConfirmed: true,
            accuracyConfirmed: true,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateApplicationSubmissionStatus.Submitted));
            Assert.That(result.AttestationDigest, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(repository.Submission, Is.Not.Null);
            Assert.That(repository.Submission!.AttestationVersion, Is.EqualTo(DomainCertificateApplicantAttestation.Version));
            Assert.That(repository.Submission.AttestationDigest, Is.EqualTo(result.AttestationDigest));
            Assert.That(repository.Submission.SubmittedAtUtc, Is.EqualTo(Now));
        });
    }

    [Test]
    public async Task Missing_declaration_cannot_submit_application()
    {
        var repository = new ApplicationRepository(ReadyEnrollment());
        var service = new DomainCertificateApplicationService(repository, new FixedTimeProvider(Now));

        var result = await service.SubmitAsync(
            "owner-1",
            "example.com",
            authorityConfirmed: true,
            accuracyConfirmed: false,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateApplicationSubmissionStatus.InvalidRequest));
            Assert.That(repository.Submission, Is.Null);
        });
    }

    [Test]
    public async Task Authorized_decision_requires_privacy_safe_reason()
    {
        var repository = new ApplicationRepository(ReadyEnrollment());
        var service = new DomainCertificateApplicationService(repository, new FixedTimeProvider(Now));

        var invalid = await service.DecideAsync(
            "enrollment-1",
            DomainCertificateApplicationStatus.Approved,
            "no",
            "admin-1",
            CancellationToken.None);
        var approved = await service.DecideAsync(
            "enrollment-1",
            DomainCertificateApplicationStatus.Approved,
            "Verified evidence and applicant authority were reviewed.",
            "admin-1",
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(invalid.Status, Is.EqualTo(DomainCertificateApplicationDecisionStatus.InvalidRequest));
            Assert.That(approved.Status, Is.EqualTo(DomainCertificateApplicationDecisionStatus.Approved));
            Assert.That(repository.Decision?.ActorId, Is.EqualTo("admin-1"));
        });
    }

    private static DomainEnrollmentStateRecord ReadyEnrollment() => new(
        "enrollment-1",
        "owner-1",
        "example.com",
        DomainEnrollmentStatus.PendingSecurityReview,
        Now.AddDays(-2),
        Now.AddDays(-1),
        Now.AddHours(-12),
        "Example",
        "Example Organization");

    private sealed class ApplicationRepository(DomainEnrollmentStateRecord enrollment) : IDomainEnrollmentRepository
    {
        public DomainCertificateApplicationSubmissionRecord? Submission { get; private set; }
        public DomainCertificateApplicationDecisionRecord? Decision { get; private set; }

        public Task<DomainEnrollmentStateRecord?> GetCurrentAsync(
            string ownerId,
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainEnrollmentStateRecord?>(
                enrollment.OwnerId == ownerId && enrollment.Domain == domain ? enrollment : null);

        public Task<DomainEnrollmentRepositoryWriteResult> TryStartEnrollmentAsync(
            DomainEnrollmentStartRecord item,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TryApplyOwnershipVerificationAsync(
            DomainOwnershipVerificationRecord item,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TryApplyWebsiteVerificationAsync(
            DomainWebsiteVerificationRecord item,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TryCompleteIdentityProfileAsync(
            DomainCertificateIdentityProfileRecord item,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TryApplySecurityReviewAsync(
            DomainCertificateSecurityReviewRecord item,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainEnrollmentTransitionWriteResult> TrySubmitApplicationAsync(
            DomainCertificateApplicationSubmissionRecord submission,
            CancellationToken cancellationToken)
        {
            Submission = submission;
            return Task.FromResult(new DomainEnrollmentTransitionWriteResult(
                DomainEnrollmentTransitionWriteStatus.Updated));
        }

        public Task<DomainEnrollmentTransitionWriteResult> TryDecideApplicationAsync(
            DomainCertificateApplicationDecisionRecord decision,
            CancellationToken cancellationToken)
        {
            Decision = decision;
            return Task.FromResult(new DomainEnrollmentTransitionWriteResult(
                DomainEnrollmentTransitionWriteStatus.Updated));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
