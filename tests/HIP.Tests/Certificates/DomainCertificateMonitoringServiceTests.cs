using HIP.Application.Certificates;
using HIP.Application.SiteSafety;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateMonitoringServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 27, 18, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Owner_opt_in_runs_an_immediate_authoritative_check_and_activates_eligible_monitoring()
    {
        var repository = new RecordingEnrollmentRepository(Enrollment());
        var promotion = new RecordingPromotionService();
        var service = new DomainCertificateMonitoringService(
            repository,
            new FixedSecurityScanService(ScanResult(score: 82)),
            promotion,
            new FixedTimeProvider(Now));

        var result = await service.StartAsync(
            "owner-1",
            "example.com",
            accountContactVerified: true,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringStartStatus.Activated));
            Assert.That(result.CurrentScore, Is.EqualTo(82));
            Assert.That(repository.Enabled, Is.Not.Null);
            Assert.That(repository.Check, Is.Null);
            Assert.That(promotion.State, Is.EqualTo(Enrollment()));
            Assert.That(promotion.Check?.TargetStatus, Is.EqualTo(DomainEnrollmentStatus.Monitored));
            Assert.That(promotion.Check?.EvidenceDigest, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(promotion.Scan?.Evaluation?.RequestedLevel, Is.EqualTo(DomainCertificateLevel.Monitored));
        });
    }

    [Test]
    public async Task Owner_opt_in_remains_enabled_when_current_evidence_is_below_monitored_threshold()
    {
        var repository = new RecordingEnrollmentRepository(Enrollment());
        var promotion = new RecordingPromotionService();
        var service = new DomainCertificateMonitoringService(
            repository,
            new FixedSecurityScanService(ScanResult(score: 66)),
            promotion,
            new FixedTimeProvider(Now));

        var result = await service.StartAsync(
            "owner-1",
            "example.com",
            accountContactVerified: true,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringStartStatus.EnabledPendingEvidence));
            Assert.That(result.CurrentScore, Is.EqualTo(66));
            Assert.That(repository.Check!.TargetStatus, Is.EqualTo(DomainEnrollmentStatus.Verified));
            Assert.That(promotion.Check, Is.Null);
        });
    }

    [Test]
    public async Task Opt_in_rejects_an_owner_without_an_active_certificate()
    {
        var repository = new RecordingEnrollmentRepository(
            Enrollment() with { CertificateStatus = DomainCertificateStatus.Suspended });
        var service = new DomainCertificateMonitoringService(
            repository,
            new FixedSecurityScanService(ScanResult(score: 82)),
            new RecordingPromotionService(),
            new FixedTimeProvider(Now));

        var result = await service.StartAsync(
            "owner-1",
            "example.com",
            accountContactVerified: true,
            CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringStartStatus.NotReady));
        Assert.That(repository.Enabled, Is.Null);
    }

    [Test]
    public async Task Provider_failure_after_opt_in_fails_safely_without_claiming_monitoring()
    {
        var repository = new RecordingEnrollmentRepository(Enrollment());
        var service = new DomainCertificateMonitoringService(
            repository,
            new ThrowingSecurityScanService(),
            new RecordingPromotionService(),
            new FixedTimeProvider(Now));

        var result = await service.StartAsync(
            "owner-1",
            "example.com",
            accountContactVerified: true,
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringStartStatus.Unavailable));
            Assert.That(repository.Enabled, Is.Not.Null);
            Assert.That(repository.Check, Is.Null);
        });
    }
    private static DomainMonitoringEnrollmentState Enrollment() =>
        new(
            "enrollment-1",
            "owner-1",
            "example.com",
            DomainEnrollmentStatus.Verified,
            DomainCertificateStatus.Active,
            DomainCertificateLevel.Verified,
            Now.AddDays(-2),
            Now.AddDays(-2),
            Now.AddDays(-1),
            MonitoringEnabledAtUtc: null,
            LastMonitoringAtUtc: null,
            CurrentScore: 78);

    private static DomainCertificateSecurityScanResult ScanResult(int score)
    {
        var evidence = new DomainCertificateEvidenceSnapshot(
            true,
            Now.AddDays(-2),
            Now.AddDays(-2),
            Now.AddDays(-1),
            true,
            0,
            true,
            true,
            true,
            true,
            ContinuousMonitoringEnabled: true,
            CertificateActive: true,
            CurrentTrustScore: score,
            LastMonitoringAtUtc: Now);
        var evaluation = new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1).Evaluate(
            new DomainCertificatePolicyEvaluationRequest(
                "example.com",
                DomainCertificateLevel.Monitored,
                evidence,
                new DomainCertificateReviewSignals(),
                Now));
        var scan = new SiteSafetyScanResult(
            "scan-1",
            "https://example.com/",
            "example.com",
            Now,
            0, 0, 0, 0, 0, 0, 0, 0,
            SiteSafetyScanStatus.Clean,
            "Clean monitoring scan.",
            ["No critical findings."],
            [], [], [],
            "High",
            score, score, score, score,
            [],
            new SiteSafetyScoreImpact(score, score, score, score, []));
        return new DomainCertificateSecurityScanResult(
            DomainCertificateSecurityScanStatus.Evaluated,
            scan,
            evaluation,
            DomainCertificatePublicRiskClassification.Low,
            []);
    }

    private sealed class RecordingEnrollmentRepository(DomainMonitoringEnrollmentState enrollment)
        : IDomainCertificateMonitoringRepository
    {
        public DomainMonitoringEnableRecord? Enabled { get; private set; }
        public DomainMonitoringCheckRecord? Check { get; private set; }

        public Task<DomainMonitoringEnrollmentState?> GetForMonitoringAsync(
            string ownerId,
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult<DomainMonitoringEnrollmentState?>(
                ownerId == enrollment.OwnerId && domain == enrollment.Domain ? enrollment : null);

        public Task<DomainMonitoringWriteStatus> TryEnableAsync(
            DomainMonitoringEnableRecord record,
            CancellationToken cancellationToken)
        {
            Enabled = record;
            return Task.FromResult(DomainMonitoringWriteStatus.Updated);
        }

        public Task<DomainMonitoringWriteStatus> TryApplyCheckAsync(
            DomainMonitoringCheckRecord record,
            CancellationToken cancellationToken)
        {
            Check = record;
            return Task.FromResult(DomainMonitoringWriteStatus.Updated);
        }

        public Task<DomainMonitoringWriteStatus> TryApplyPromotedCheckAsync(
            DomainMonitoringCertificatePromotionRecord promotion,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }


    private sealed class RecordingPromotionService : IDomainCertificateMonitoringPromotionService
    {
        public DomainMonitoringEnrollmentState? State { get; private set; }
        public DomainCertificateSecurityScanResult? Scan { get; private set; }
        public DomainMonitoringCheckRecord? Check { get; private set; }

        public Task<DomainCertificateMonitoringPromotionResult> PromoteAsync(
            DomainMonitoringEnrollmentState state,
            DomainCertificateSecurityScanResult scan,
            DomainMonitoringCheckRecord check,
            CancellationToken cancellationToken)
        {
            State = state;
            Scan = scan;
            Check = check;
            return Task.FromResult(new DomainCertificateMonitoringPromotionResult(
                DomainCertificateMonitoringPromotionStatus.Promoted));
        }
    }
    private sealed class FixedSecurityScanService(DomainCertificateSecurityScanResult result)
        : IDomainCertificateSecurityScanService
    {
        public Task<DomainCertificateSecurityScanResult> ScanAsync(
            DomainCertificateSecurityScanRequest request,
            CancellationToken cancellationToken) => Task.FromResult(result);
    }

    private sealed class ThrowingSecurityScanService : IDomainCertificateSecurityScanService
    {
        public Task<DomainCertificateSecurityScanResult> ScanAsync(
            DomainCertificateSecurityScanRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("provider unavailable");
    }
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
