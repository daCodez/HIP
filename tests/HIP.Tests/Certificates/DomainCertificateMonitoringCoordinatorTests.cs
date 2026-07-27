using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateMonitoringCoordinatorTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 27, 20, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Due_monitoring_runs_a_bounded_authenticated_check()
    {
        var repository = new RecordingScheduleRepository([Enrollment()]);
        var service = new RecordingMonitoringService(
            new DomainCertificateMonitoringStartResult(
                DomainCertificateMonitoringStartStatus.Activated,
                82,
                Now));
        var coordinator = new DomainCertificateMonitoringCoordinator(
            repository,
            service,
            new FixedTimeProvider(Now));

        var summary = await coordinator.RunDueAsync(100, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary, Is.EqualTo(new DomainMonitoringCycleSummary(1, 1, 0, 0)));
            Assert.That(service.Domains, Is.EqualTo(new[] { "example.com" }));
            Assert.That(service.AccountContactValues, Is.EqualTo(new[] { true }));
            Assert.That(repository.Failures, Is.Empty);
        });
    }

    [Test]
    public async Task Unavailable_check_records_exponential_retry_without_error_details()
    {
        var repository = new RecordingScheduleRepository(
            [Enrollment() with { MonitoringFailureCount = 2 }]);
        var service = new RecordingMonitoringService(
            new DomainCertificateMonitoringStartResult(
                DomainCertificateMonitoringStartStatus.Unavailable));
        var coordinator = new DomainCertificateMonitoringCoordinator(
            repository,
            service,
            new FixedTimeProvider(Now));

        var summary = await coordinator.RunDueAsync(100, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(summary, Is.EqualTo(new DomainMonitoringCycleSummary(1, 0, 1, 0)));
            Assert.That(repository.Failures, Has.Count.EqualTo(1));
            Assert.That(repository.Failures[0].ExpectedFailureCount, Is.EqualTo(2));
            Assert.That(repository.Failures[0].NextCheckAtUtc, Is.EqualTo(Now.AddHours(4)));
            Assert.That(repository.Failures[0].AuditEventId,
                Does.Match("^certificate-event:monitoring-deferred:[0-9a-f]{48}$"));
        });
    }

    [TestCase(0)]
    [TestCase(501)]
    public void Run_due_rejects_unbounded_batch_sizes(int maximum)
    {
        var coordinator = new DomainCertificateMonitoringCoordinator(
            new RecordingScheduleRepository([]),
            new RecordingMonitoringService(
                new DomainCertificateMonitoringStartResult(
                    DomainCertificateMonitoringStartStatus.Unavailable)),
            new FixedTimeProvider(Now));

        Assert.That(
            async () => await coordinator.RunDueAsync(maximum, CancellationToken.None),
            Throws.TypeOf<ArgumentOutOfRangeException>());
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
            MonitoringEnabledAtUtc: Now.AddDays(-1),
            LastMonitoringAtUtc: Now.AddDays(-1),
            CurrentScore: 76,
            MonitoringNextCheckAtUtc: Now.AddMinutes(-1),
            MonitoringFailureCount: 0);

    private sealed class RecordingScheduleRepository(
        IReadOnlyList<DomainMonitoringEnrollmentState> due)
        : IDomainCertificateMonitoringScheduleRepository
    {
        public List<DomainMonitoringFailureRecord> Failures { get; } = [];

        public Task<IReadOnlyList<DomainMonitoringEnrollmentState>> ListDueAsync(
            DateTimeOffset dueAtUtc,
            int maximum,
            CancellationToken cancellationToken) =>
            Task.FromResult(due);

        public Task<DomainMonitoringWriteStatus> TryRecordFailureAsync(
            DomainMonitoringFailureRecord record,
            CancellationToken cancellationToken)
        {
            Failures.Add(record);
            return Task.FromResult(DomainMonitoringWriteStatus.Updated);
        }
    }

    private sealed class RecordingMonitoringService(DomainCertificateMonitoringStartResult result)
        : IDomainCertificateMonitoringService
    {
        public List<string> Domains { get; } = [];
        public List<bool> AccountContactValues { get; } = [];

        public Task<DomainCertificateMonitoringStartResult> StartAsync(
            string ownerId,
            string domain,
            bool accountContactVerified,
            CancellationToken cancellationToken)
        {
            Domains.Add(domain);
            AccountContactValues.Add(accountContactVerified);
            return Task.FromResult(result);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
