using System.Security.Cryptography;
using System.Text;
using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Entities;
using HIP.Infrastructure.Persistence.Repositories;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 24, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Certificate_and_issuance_event_are_created_together()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();

        var result = await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.Created));
            Assert.That(result.StoredCertificate, Is.EqualTo(record));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Single().EventType, Is.EqualTo("CertificateIssued"));
            Assert.That(context.DomainCertificateEvents.Single().EvidenceDigest,
                Is.EqualTo(record.SourceDecisionDigest));
        });
    }

    [Test]
    public async Task Exact_retry_returns_existing_without_duplicate_audit_event()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        var retry = await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(retry.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.ExistingSame));
            Assert.That(retry.StoredCertificate?.SignedCertificateJson,
                Is.EqualTo(record.SignedCertificateJson));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Changed_decision_digest_for_same_certificate_id_is_a_conflict()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);

        var conflict = await repository.TryCreateIssuedAsync(
            record with { SourceDecisionDigest = $"sha256:{new string('b', 64)}" },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(conflict.Status, Is.EqualTo(DomainCertificateRepositoryWriteStatus.Conflict));
            Assert.That(context.DomainCertificates.Count(), Is.EqualTo(1));
            Assert.That(context.DomainCertificateEvents.Count(), Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Indexed_data_that_disagrees_with_signed_certificate_is_rejected()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);
        context.ChangeTracker.Clear();
        var entity = await context.DomainCertificates.SingleAsync();
        entity.Domain = "tampered.example";
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        Assert.That(
            async () => await repository.GetByIdAsync(
                record.Certificate.Payload.CertificateId,
                CancellationToken.None),
            Throws.TypeOf<InvalidOperationException>());
    }

    [Test]
    public async Task PostgreSql_microsecond_precision_does_not_invalidate_signed_certificate_timestamps()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = RecordWithSubMicrosecondTimestamps();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);
        context.ChangeTracker.Clear();

        var certificate = await context.DomainCertificates.SingleAsync();
        certificate.IssuedAtUtc = ToPostgreSqlPrecision(certificate.IssuedAtUtc!.Value);
        certificate.ExpiresAtUtc = ToPostgreSqlPrecision(certificate.ExpiresAtUtc!.Value);
        certificate.LastVerificationAtUtc = ToPostgreSqlPrecision(certificate.LastVerificationAtUtc!.Value);
        certificate.LastMonitoringAtUtc = ToPostgreSqlPrecision(certificate.LastMonitoringAtUtc!.Value);
        var issuanceEvent = await context.DomainCertificateEvents.SingleAsync();
        issuanceEvent.OccurredAtUtc = ToPostgreSqlPrecision(issuanceEvent.OccurredAtUtc);
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        var loaded = await repository.GetCurrentByDomainAsync("example.com", CancellationToken.None);

        Assert.That(loaded?.SignedCertificateJson, Is.EqualTo(record.SignedCertificateJson));
    }

    [Test]
    public async Task Live_status_can_change_without_rewriting_the_signed_issuance_payload()
    {
        await using var context = Context();
        var repository = Repository(context);
        var record = Record();
        await repository.TryCreateIssuedAsync(record, CancellationToken.None);
        context.ChangeTracker.Clear();
        var entity = await context.DomainCertificates.SingleAsync();
        entity.Status = DomainCertificateStatus.Suspended;
        await context.SaveChangesAsync();
        context.ChangeTracker.Clear();

        var stored = await repository.GetByIdAsync(
            record.Certificate.Payload.CertificateId,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(stored?.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Suspended));
            Assert.That(stored?.Certificate.Payload.Status, Is.EqualTo(DomainCertificateStatus.Active));
        });
    }

    [Test]
    public async Task Certificate_transition_updates_live_status_and_appends_reasoned_audit_without_rewriting_signature()
    {
        await using var context = Context();
        var repository = Repository(context);
        var issued = Record();
        await repository.TryCreateIssuedAsync(issued, CancellationToken.None);
        var transition = new DomainCertificateStatusTransition(
            issued.Certificate.Payload.CertificateId,
            DomainCertificateStatus.Active,
            DomainCertificateStatus.Suspended,
            "admin-1",
            "monitoring-stale",
            "Monitoring evidence is stale.",
            Now.AddMinutes(5),
            "certificate-event:suspend-1");

        var applied = await repository.TryTransitionStatusAsync(transition, CancellationToken.None);
        var retry = await repository.TryTransitionStatusAsync(transition, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied.Status, Is.EqualTo(DomainCertificateTransitionWriteStatus.Updated));
            Assert.That(retry.Status, Is.EqualTo(DomainCertificateTransitionWriteStatus.ExistingSame));
            var certificate = context.DomainCertificates.Single();
            Assert.That(certificate.Status, Is.EqualTo(DomainCertificateStatus.Suspended));
            Assert.That(certificate.SignedCertificateJson, Is.EqualTo(issued.SignedCertificateJson));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "CertificateSuspended");
            Assert.That(auditEvent.ActorId, Is.EqualTo("admin-1"));
            Assert.That(auditEvent.ReasonCode, Is.EqualTo("monitoring-stale"));
            Assert.That(auditEvent.PreviousStatus, Is.EqualTo(DomainCertificateStatus.Active.ToString()));
            Assert.That(auditEvent.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Suspended.ToString()));
        });
    }

    [Test]
    public async Task Owner_summary_query_is_exactly_scoped_and_uses_current_persisted_state()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-other",
            OwnerId = "owner-other",
            Domain = "private.example",
            Status = DomainEnrollmentStatus.PendingOwnership,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now,
            AggregateVersion = 1
        });
        await context.SaveChangesAsync();

        var summaries = await repository.ListForOwnerAsync(
            "owner-1",
            offset: 0,
            limit: 25,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summaries, Has.Count.EqualTo(1));
            Assert.That(summaries[0].Domain, Is.EqualTo("example.com"));
            Assert.That(summaries[0].EnrollmentStatus, Is.EqualTo(DomainEnrollmentStatus.Verified));
            Assert.That(summaries[0].CertificateId, Is.EqualTo("hip-domain-cert-0001"));
            Assert.That(summaries[0].CertificateStatus, Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(summaries[0].BadgeLevel, Is.EqualTo(DomainCertificateLevel.Verified));
            Assert.That(summaries, Has.None.Matches<OwnerDomainCertificateSummary>(
                item => item.Domain == "private.example"));
        });
    }

    [Test]
    public async Task Enrollment_start_is_idempotent_and_commits_an_audit_event()
    {
        await using var context = Context();
        var repository = Repository(context);
        var candidate = new DomainEnrollmentStartRecord(
            "enrollment-new",
            "owner-1",
            "new.example",
            DomainEnrollmentStatus.PendingOwnership,
            DomainCertificatePolicy.V1.Version,
            Now,
            "certificate-event:enrollment-new");

        var created = await repository.TryStartEnrollmentAsync(candidate, CancellationToken.None);
        var retry = await repository.TryStartEnrollmentAsync(
            candidate with { CreatedAtUtc = Now.AddMinutes(1) },
            CancellationToken.None);
        var conflict = await repository.TryStartEnrollmentAsync(
            candidate with { EnrollmentId = "enrollment-other", OwnerId = "owner-other" },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(created.Status, Is.EqualTo(DomainEnrollmentRepositoryWriteStatus.Created));
            Assert.That(retry.Status, Is.EqualTo(DomainEnrollmentRepositoryWriteStatus.ExistingSame));
            Assert.That(conflict.Status, Is.EqualTo(DomainEnrollmentRepositoryWriteStatus.Conflict));
            Assert.That(context.DomainEnrollments.Count(item => item.Domain == "new.example"), Is.EqualTo(1));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EnrollmentId == "enrollment-new");
            Assert.That(auditEvent.EventType, Is.EqualTo("EnrollmentStarted"));
            Assert.That(auditEvent.ActorId, Is.EqualTo("owner-1"));
            Assert.That(auditEvent.CertificateId, Is.Null);
        });
    }

    [Test]
    public async Task Ownership_verification_advances_once_and_appends_an_audit_event()
    {
        await using var context = Context();
        var repository = Repository(context);
        var started = new DomainEnrollmentStartRecord(
            "enrollment-verify",
            "owner-1",
            "verify.example",
            DomainEnrollmentStatus.PendingOwnership,
            DomainCertificatePolicy.V1.Version,
            Now,
            "certificate-event:enrollment-verify");
        await repository.TryStartEnrollmentAsync(started, CancellationToken.None);
        var verification = new DomainOwnershipVerificationRecord(
            "enrollment-verify",
            "owner-1",
            "verify.example",
            VerificationMethod.DnsTxt,
            Now.AddMinutes(5),
            "certificate-event:ownership-verify");

        var applied = await repository.TryApplyOwnershipVerificationAsync(verification, CancellationToken.None);
        var retry = await repository.TryApplyOwnershipVerificationAsync(verification, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(retry.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.AlreadyApplied));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-verify");
            Assert.That(enrollment.Status, Is.EqualTo(DomainEnrollmentStatus.OwnershipVerified));
            Assert.That(enrollment.DnsVerifiedAtUtc, Is.EqualTo(Now.AddMinutes(5)));
            Assert.That(context.DomainCertificateEvents.Count(item => item.EnrollmentId == "enrollment-verify"), Is.EqualTo(2));
            Assert.That(context.DomainCertificateEvents.Single(item => item.EventType == "DomainOwnershipVerified").ActorId,
                Is.EqualTo("owner-1"));
        });
    }

    [Test]
    public async Task Website_verification_is_owner_scoped_advances_once_and_appends_an_audit_event()
    {
        await using var context = Context();
        var repository = Repository(context);
        var started = new DomainEnrollmentStartRecord(
            "enrollment-website", "owner-1", "website.example", DomainEnrollmentStatus.PendingOwnership,
            DomainCertificatePolicy.V1.Version, Now, "certificate-event:enrollment-website");
        await repository.TryStartEnrollmentAsync(started, CancellationToken.None);
        await repository.TryApplyOwnershipVerificationAsync(
            new DomainOwnershipVerificationRecord(
                "enrollment-website", "owner-1", "website.example", VerificationMethod.DnsTxt,
                Now.AddMinutes(5), "certificate-event:ownership-website"),
            CancellationToken.None);
        var verification = new DomainWebsiteVerificationRecord(
            "enrollment-website", "owner-1", "website.example", VerificationMethod.WellKnownHipJson,
            Now.AddMinutes(10), "certificate-event:website-verify");

        var hidden = await repository.GetCurrentAsync("owner-other", "website.example", CancellationToken.None);
        var applied = await repository.TryApplyWebsiteVerificationAsync(verification, CancellationToken.None);
        var retry = await repository.TryApplyWebsiteVerificationAsync(verification, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(hidden, Is.Null);
            Assert.That(applied.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(retry.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.AlreadyApplied));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-website");
            Assert.That(enrollment.Status, Is.EqualTo(DomainEnrollmentStatus.PendingSecurityReview));
            Assert.That(enrollment.WebsiteVerifiedAtUtc, Is.EqualTo(Now.AddMinutes(10)));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "WebsiteControlVerified");
            Assert.That(auditEvent.ActorId, Is.EqualTo("owner-1"));
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain("challenge"));
        });
    }

    [Test]
    public async Task Identity_profile_stores_only_privacy_filtered_fields_and_appends_audit()
    {
        await using var context = Context();
        var repository = Repository(context);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-profile",
            OwnerId = "owner-1",
            Domain = "profile.example",
            Status = DomainEnrollmentStatus.PendingSecurityReview,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now,
            DnsVerifiedAtUtc = Now,
            WebsiteVerifiedAtUtc = Now,
            AggregateVersion = 1
        });
        await context.SaveChangesAsync();
        var profile = new DomainCertificateIdentityProfileRecord(
            "enrollment-profile", "owner-1", "profile.example", "Example", "Example Org",
            "https://profile.example/contact", null, $"sha256:{new string('a', 64)}",
            Now.AddMinutes(5), "certificate-event:profile-complete");

        var applied = await repository.TryCompleteIdentityProfileAsync(profile, CancellationToken.None);
        var retry = await repository.TryCompleteIdentityProfileAsync(profile, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(retry.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.AlreadyApplied));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-profile");
            Assert.That(enrollment.PublicDisplayName, Is.EqualTo("Example"));
            Assert.That(enrollment.PublicOrganizationName, Is.EqualTo("Example Org"));
            Assert.That(enrollment.PublicWebsiteContact, Is.EqualTo("https://profile.example/contact"));
            Assert.That(enrollment.SecurityContactHash, Is.EqualTo(profile.SecurityContactHash));
            Assert.That(enrollment.IdentityCompletedAtUtc, Is.EqualTo(Now.AddMinutes(5)));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "IdentityProfileCompleted");
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain(profile.SecurityContactHash));
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain("contact"));
        });
    }

    [Test]
    public async Task Eligible_security_review_updates_projection_and_appends_digest_bound_audit()
    {
        await using var context = Context();
        var repository = Repository(context);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-review",
            OwnerId = "owner-1",
            Domain = "review.example",
            Status = DomainEnrollmentStatus.PendingSecurityReview,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now,
            DnsVerifiedAtUtc = Now,
            WebsiteVerifiedAtUtc = Now,
            IdentityCompletedAtUtc = Now,
            PublicDisplayName = "Review Example",
            ApplicationStatus = DomainCertificateApplicationStatus.Approved,
            ApplicationSubmittedAtUtc = Now.AddMinutes(2),
            ApplicationReviewedAtUtc = Now.AddMinutes(5),
            ApplicantAttestationDigest = $"sha256:{new string('a', 64)}",
            AggregateVersion = 1
        });
        await context.SaveChangesAsync();
        var review = new DomainCertificateSecurityReviewRecord(
            "enrollment-review", "owner-1", "review.example",
            DomainCertificatePolicyDecision.Eligible, 84, 0,
            $"sha256:{new string('d', 64)}", Now.AddMinutes(10),
            "certificate-event:security-review");

        var applied = await repository.TryApplySecurityReviewAsync(review, CancellationToken.None);
        var retry = await repository.TryApplySecurityReviewAsync(review, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.Updated));
            Assert.That(retry.Status, Is.EqualTo(DomainEnrollmentTransitionWriteStatus.AlreadyApplied));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-review");
            Assert.That(enrollment.Status, Is.EqualTo(DomainEnrollmentStatus.Verified));
            Assert.That(enrollment.CurrentScore, Is.EqualTo(84));
            Assert.That(enrollment.SecurityReviewCompletedAtUtc, Is.EqualTo(Now.AddMinutes(10)));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "SecurityReviewPassed");
            Assert.That(auditEvent.EvidenceDigest, Is.EqualTo(review.EvidenceDigest));
            Assert.That(auditEvent.ActorId, Is.EqualTo("owner-1"));
        });
    }
    [Test]
    public async Task Monitoring_opt_in_is_owner_bound_idempotent_and_audited()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        var enabledAt = Now.AddMinutes(20);
        var record = new DomainMonitoringEnableRecord(
            "enrollment-1", "owner-1", "example.com", enabledAt, enabledAt,
            "certificate-event:monitoring-enabled:enrollment-1");

        var applied = await repository.TryEnableAsync(record, CancellationToken.None);
        var retry = await repository.TryEnableAsync(record, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied, Is.EqualTo(DomainMonitoringWriteStatus.Updated));
            Assert.That(retry, Is.EqualTo(DomainMonitoringWriteStatus.Existing));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1");
            Assert.That(enrollment.MonitoringEnabledAtUtc, Is.EqualTo(enabledAt));
            Assert.That(enrollment.MonitoringNextCheckAtUtc, Is.EqualTo(enabledAt));
            Assert.That(enrollment.MonitoringFailureCount, Is.Zero);
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "MonitoringEnabled");
            Assert.That(auditEvent.ActorId, Is.EqualTo("owner-1"));
            Assert.That(auditEvent.ReasonCode, Is.EqualTo("OwnerOptIn"));
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain("owner-1"));
        });
    }

    [Test]
    public async Task Monitoring_check_promotes_eligible_enrollment_and_stores_digest_bound_audit()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        var enabledAt = Now.AddMinutes(20);
        await repository.TryEnableAsync(
            new DomainMonitoringEnableRecord(
                "enrollment-1", "owner-1", "example.com", enabledAt, enabledAt,
                "certificate-event:monitoring-enabled:enrollment-1"),
            CancellationToken.None);
        var evidenceDigest = $"sha256:{new string('e', 64)}";
        var checkedAt = enabledAt.AddMinutes(1);
        var check = new DomainMonitoringCheckRecord(
            "enrollment-1", "owner-1", "example.com",
            DomainEnrollmentStatus.Verified, DomainEnrollmentStatus.Monitored,
            82, 0, checkedAt, checkedAt.AddHours(24), evidenceDigest,
            "certificate-event:monitoring-check:eligible");

        var applied = await repository.TryApplyCheckAsync(check, CancellationToken.None);
        var retry = await repository.TryApplyCheckAsync(check, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied, Is.EqualTo(DomainMonitoringWriteStatus.Updated));
            Assert.That(retry, Is.EqualTo(DomainMonitoringWriteStatus.Existing));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1");
            Assert.That(enrollment.Status, Is.EqualTo(DomainEnrollmentStatus.Monitored));
            Assert.That(enrollment.CurrentScore, Is.EqualTo(82));
            Assert.That(enrollment.LastMonitoringAtUtc, Is.EqualTo(checkedAt));
            Assert.That(enrollment.MonitoringNextCheckAtUtc, Is.EqualTo(checkedAt.AddHours(24)));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "MonitoringPolicySatisfied");
            Assert.That(auditEvent.ActorId, Is.EqualTo("hip-monitoring-service"));
            Assert.That(auditEvent.EvidenceDigest, Is.EqualTo(evidenceDigest));
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain("82"));
        });
    }
    [TestCase(DomainCertificateLevel.Verified, DomainEnrollmentStatus.Verified)]
    [TestCase(DomainCertificateLevel.Monitored, DomainEnrollmentStatus.Verified)]
    [TestCase(DomainCertificateLevel.Monitored, DomainEnrollmentStatus.Monitored)]
    public async Task Monitoring_promotion_atomically_replaces_current_signed_certificate_and_is_idempotent(
        DomainCertificateLevel currentLevel,
        DomainEnrollmentStatus currentEnrollmentStatus)
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        context.DomainCertificates.Single(item => item.CertificateId == "hip-domain-cert-0001").Level = currentLevel;
        await context.SaveChangesAsync();
        var enabledAt = Now.AddMinutes(20);
        await repository.TryEnableAsync(
            new DomainMonitoringEnableRecord(
                "enrollment-1", "owner-1", "example.com", enabledAt, enabledAt,
                "certificate-event:monitoring-enabled:enrollment-1"),
            CancellationToken.None);
        context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1").Status = currentEnrollmentStatus;
        await context.SaveChangesAsync();
        var checkedAt = enabledAt.AddMinutes(1);
        var check = new DomainMonitoringCheckRecord(
            "enrollment-1", "owner-1", "example.com",
            currentEnrollmentStatus, DomainEnrollmentStatus.Monitored,
            82, 0, checkedAt, checkedAt.AddHours(24), $"sha256:{new string('e', 64)}",
            "certificate-event:monitoring-check:promoted");
        var promoted = PromotedRecord(checkedAt);
        var promotion = new DomainMonitoringCertificatePromotionRecord(
            check, "hip-domain-cert-0001", 1, promoted);

        var applied = await repository.TryApplyPromotedCheckAsync(promotion, CancellationToken.None);
        context.ChangeTracker.Clear();
        var retry = await repository.TryApplyPromotedCheckAsync(promotion, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied, Is.EqualTo(DomainMonitoringWriteStatus.Updated));
            Assert.That(retry, Is.EqualTo(DomainMonitoringWriteStatus.Existing));
            var certificates = context.DomainCertificates.OrderBy(item => item.CertificateVersion).ToArray();
            Assert.That(certificates, Has.Length.EqualTo(2));
            Assert.That(certificates[0].IsCurrent, Is.False);
            Assert.That(certificates[1].IsCurrent, Is.True);
            Assert.That(certificates[1].Level, Is.EqualTo(DomainCertificateLevel.Monitored));
            Assert.That(certificates[1].LastMonitoringAtUtc, Is.EqualTo(checkedAt));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1");
            Assert.That(enrollment.Status, Is.EqualTo(DomainEnrollmentStatus.Monitored));
            Assert.That(enrollment.CurrentScore, Is.EqualTo(82));
            Assert.That(context.DomainCertificateEvents.Count(item => item.EventType == "CertificateIssued"),
                Is.EqualTo(2));
            var monitoringEvent = context.DomainCertificateEvents.Single(
                item => item.EventType == "MonitoringPolicySatisfied");
            Assert.That(monitoringEvent.CertificateId, Is.EqualTo("hip-domain-cert-0002"));
            Assert.That(monitoringEvent.EvidenceDigest, Is.EqualTo(check.EvidenceDigest));
        });

        var current = await repository.GetCurrentByDomainAsync("example.com", CancellationToken.None);
        Assert.That(current?.Certificate.Payload.CertificateId, Is.EqualTo("hip-domain-cert-0002"));
    }
    [Test]
    public async Task Due_monitoring_query_returns_only_active_scheduled_certificates()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1");
        enrollment.MonitoringEnabledAtUtc = Now.AddDays(-1);
        enrollment.MonitoringNextCheckAtUtc = Now.AddMinutes(-1);
        await context.SaveChangesAsync();

        var due = await repository.ListDueAsync(Now, 100, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(due, Has.Count.EqualTo(1));
            Assert.That(due[0].EnrollmentId, Is.EqualTo("enrollment-1"));
            Assert.That(due[0].MonitoringNextCheckAtUtc, Is.EqualTo(Now.AddMinutes(-1)));
            Assert.That(due[0].MonitoringFailureCount, Is.Zero);
        });
    }

    [Test]
    public async Task Monitoring_failure_schedules_idempotent_privacy_safe_retry()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        var enabledAt = Now.AddMinutes(20);
        await repository.TryEnableAsync(
            new DomainMonitoringEnableRecord(
                "enrollment-1", "owner-1", "example.com", enabledAt, enabledAt,
                "certificate-event:monitoring-enabled:enrollment-1"),
            CancellationToken.None);
        var failure = new DomainMonitoringFailureRecord(
            "enrollment-1", "owner-1", "example.com", 0,
            enabledAt.AddMinutes(1), enabledAt.AddHours(1),
            "certificate-event:monitoring-deferred:test");

        var applied = await repository.TryRecordFailureAsync(failure, CancellationToken.None);
        var retry = await repository.TryRecordFailureAsync(failure, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(applied, Is.EqualTo(DomainMonitoringWriteStatus.Updated));
            Assert.That(retry, Is.EqualTo(DomainMonitoringWriteStatus.Existing));
            var enrollment = context.DomainEnrollments.Single(item => item.EnrollmentId == "enrollment-1");
            Assert.That(enrollment.MonitoringFailureCount, Is.EqualTo(1));
            Assert.That(enrollment.MonitoringNextCheckAtUtc, Is.EqualTo(enabledAt.AddHours(1)));
            var auditEvent = context.DomainCertificateEvents.Single(item => item.EventType == "MonitoringCheckDeferred");
            Assert.That(auditEvent.ActorId, Is.EqualTo("hip-monitoring-service"));
            Assert.That(auditEvent.ReasonCode, Is.EqualTo("EvidenceUnavailable"));
            Assert.That(auditEvent.PublicSummary, Does.Not.Contain("exception").IgnoreCase);
        });
    }
    [Test]
    public async Task Admin_summary_query_pages_real_cross_owner_state_without_owner_identifiers()
    {
        await using var context = Context();
        var repository = Repository(context);
        await repository.TryCreateIssuedAsync(Record(), CancellationToken.None);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-admin-pending",
            OwnerId = "owner-private",
            Domain = "pending.example",
            Status = DomainEnrollmentStatus.PendingSecurityReview,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now,
            UpdatedAtUtc = Now,
            UnresolvedCriticalFindings = 1,
            AggregateVersion = 1
        });
        await context.SaveChangesAsync();

        var summaries = await repository.ListForAdminAsync(0, 25, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summaries, Has.Count.EqualTo(2));
            Assert.That(summaries.Select(item => item.Domain), Is.EqualTo(new[] { "example.com", "pending.example" }));
            Assert.That(summaries.Single(item => item.Domain == "example.com").CertificateStatus,
                Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(summaries.Single(item => item.Domain == "pending.example").UnresolvedCriticalFindings,
                Is.EqualTo(1));
            Assert.That(typeof(AdminDomainCertificateSummary).GetProperty("OwnerId"), Is.Null);
        });
    }

    private static HipDbContext Context()
    {
        var options = new DbContextOptionsBuilder<HipDbContext>()
            .UseInMemoryDatabase($"hip-domain-certificate-repository-{Guid.NewGuid():N}")
            .Options;
        var context = new HipDbContext(options);
        context.DomainEnrollments.Add(new HipDomainEnrollmentEntity
        {
            EnrollmentId = "enrollment-1",
            OwnerId = "owner-1",
            Domain = "example.com",
            Status = DomainEnrollmentStatus.Verified,
            PolicyVersion = DomainCertificatePolicy.V1.Version,
            CreatedAtUtc = Now.AddHours(-1),
            UpdatedAtUtc = Now,
            AggregateVersion = 1
        });
        context.SaveChanges();
        return context;
    }

    private static EfDomainCertificateRepository Repository(HipDbContext context) =>
        new(context, new Rfc8785CanonicalJsonService());

    private static HipStoredDomainCertificate Record()
    {
        var payload = new DomainTrustCertificatePayload(
            "hip-domain-cert-0001",
            1,
            DomainCertificatePolicy.V1.Version,
            "example.com",
            "Example Site",
            "Example Organization",
            DomainCertificateLevel.Verified,
            DomainCertificateStatus.Active,
            Now,
            Now.AddDays(365),
            Now.AddMinutes(-10),
            null,
            "registrant-key-1",
            [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            DomainCertificatePublicRiskClassification.Low,
            ["scan.no-critical", "tls.valid"],
            "https://hiptrust.com/api/v1/certificates/hip-domain-cert-0001/status",
            "https://hiptrust.com/certificate/hip-domain-cert-0001");
        var certificate = new SignedDomainTrustCertificate(
            payload,
            new DomainTrustCertificateSignature(
                "hip:service:domain-certificate-authority",
                "certificate-key-1",
                "test-signature-v1",
                SignatureAlgorithmFamily.Unknown,
                HipProtocolSignature.Rfc8785Canonicalization,
                "test-signature"));
        var json = DomainTrustCertificateJson.Serialize(certificate);
        return new HipStoredDomainCertificate(
            "enrollment-1",
            "owner-1",
            certificate,
            json,
            Digest(json),
            $"sha256:{new string('c', 64)}",
            new DomainCertificateAuditEvent(
                "certificate-event-1",
                "actor-1",
                "CertificateIssued",
                null,
                DomainCertificateStatus.Active,
                null,
                "HIP issued the domain certificate.",
                Now));
    }

    private static HipStoredDomainCertificate RecordWithSubMicrosecondTimestamps()
    {
        var original = Record();
        var issuedAtUtc = Now.AddTicks(4);
        var payload = original.Certificate.Payload with
        {
            IssuedAtUtc = issuedAtUtc,
            ExpiresAtUtc = Now.AddDays(365).AddTicks(4),
            LastVerificationAtUtc = Now.AddMinutes(-10).AddTicks(4),
            LastMonitoringAtUtc = Now.AddMinutes(-5).AddTicks(4)
        };
        var certificate = original.Certificate with { Payload = payload };
        var json = DomainTrustCertificateJson.Serialize(certificate);
        return original with
        {
            Certificate = certificate,
            SignedCertificateJson = json,
            CertificateDigest = Digest(json),
            IssuanceEvent = original.IssuanceEvent with { OccurredAtUtc = issuedAtUtc }
        };
    }

    private static DateTimeOffset ToPostgreSqlPrecision(DateTimeOffset value) =>
        value.AddTicks(-(value.Ticks % TimeSpan.TicksPerMicrosecond));
    private static HipStoredDomainCertificate PromotedRecord(DateTimeOffset checkedAt)
    {
        var original = Record();
        var payload = original.Certificate.Payload with
        {
            CertificateId = "hip-domain-cert-0002",
            CertificateVersion = 2,
            Level = DomainCertificateLevel.Monitored,
            IssuedAtUtc = checkedAt,
            ExpiresAtUtc = checkedAt.AddDays(365),
            LastMonitoringAtUtc = checkedAt,
            RevocationStatusUrl = "https://hiptrust.com/api/v1/certificates/hip-domain-cert-0002/status",
            PublicCertificateUrl = "https://hiptrust.com/certificate/hip-domain-cert-0002"
        };
        var certificate = original.Certificate with { Payload = payload };
        var json = DomainTrustCertificateJson.Serialize(certificate);
        return new HipStoredDomainCertificate(
            "enrollment-1",
            "owner-1",
            certificate,
            json,
            Digest(json),
            $"sha256:{new string('d', 64)}",
            new DomainCertificateAuditEvent(
                "certificate-event-2",
                "hip-monitoring-service",
                "CertificateIssued",
                null,
                DomainCertificateStatus.Active,
                null,
                "HIP issued the monitored domain certificate.",
                checkedAt));
    }

    private static string Digest(string json)
    {
        var canonical = new Rfc8785CanonicalJsonService()
            .Canonicalize(Encoding.UTF8.GetBytes(json));
        return $"sha256:{Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()}";
    }
}
