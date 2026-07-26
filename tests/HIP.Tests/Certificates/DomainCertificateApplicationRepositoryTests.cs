using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Entities;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateApplicationRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 26, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Submission_and_admin_decision_append_digest_bound_audit_events()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-certificate-application-{Guid.NewGuid():N}")
            .Options;
        await using var context = new HipDbContext(options);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-1",
            OwnerId = "owner-1",
            Domain = "example.com",
            Status = DomainEnrollmentStatus.PendingSecurityReview,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now.AddDays(-2),
            UpdatedAtUtc = Now.AddDays(-1),
            DnsVerifiedAtUtc = Now.AddDays(-2),
            WebsiteVerifiedAtUtc = Now.AddDays(-1),
            IdentityCompletedAtUtc = Now.AddHours(-12),
            PublicDisplayName = "Example",
            AggregateVersion = 1
        });
        await context.SaveChangesAsync();
        var repository = new EfDomainCertificateRepository(context, new Rfc8785CanonicalJsonService());
        var digest = $"sha256:{new string('a', 64)}";

        var submitted = await repository.TrySubmitApplicationAsync(
            new DomainCertificateApplicationSubmissionRecord(
                "enrollment-1",
                "owner-1",
                "example.com",
                DomainCertificateApplicantAttestation.Version,
                digest,
                Now,
                "certificate-event:application-1"),
            CancellationToken.None);
        var decided = await repository.TryDecideApplicationAsync(
            new DomainCertificateApplicationDecisionRecord(
                "enrollment-1",
                DomainCertificateApplicationStatus.Approved,
                "Authenticated application evidence was reviewed.",
                "admin-1",
                Now.AddMinutes(5),
                "certificate-event:decision-1"),
            CancellationToken.None);

        var enrollment = await context.DomainEnrollments.SingleAsync();
        var events = await context.DomainCertificateEvents.OrderBy(item => item.OccurredAtUtc).ToArrayAsync();
        Assert.Multiple(() =>
        {
            Assert.That(submitted.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(decided.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(enrollment.ApplicationStatus, Is.EqualTo(DomainCertificateApplicationStatus.Approved));
            Assert.That(enrollment.ApplicantAttestationDigest, Is.EqualTo(digest));
            Assert.That(events.Select(item => item.EventType), Is.EqualTo(new[]
            {
                "CertificateApplicationSubmitted",
                "CertificateApplicationApproved"
            }));
            Assert.That(events.All(item => item.EvidenceDigest == digest), Is.True);
            Assert.That(events[1].ActorId, Is.EqualTo("admin-1"));
            Assert.That(enrollment.ApplicationDecisionReason, Is.EqualTo("Authenticated application evidence was reviewed."));
            Assert.That(events[1].PublicSummary, Does.Not.Contain("evidence"));
        });
    }
}
