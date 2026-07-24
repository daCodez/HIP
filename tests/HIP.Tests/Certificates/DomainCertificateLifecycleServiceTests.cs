using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateLifecycleServiceTests
{
    [Test]
    public async Task Authorized_suspend_records_reasoned_transition()
    {
        var lifecycleRepository = new FakeLifecycleRepository();
        var service = Service(Stored(DomainCertificateStatus.Active), lifecycleRepository);

        var result = await service.ChangeStatusAsync(
            new DomainCertificateLifecycleRequest(
                "hip-domain-cert-0001",
                DomainCertificateStatus.Suspended,
                "Monitoring evidence is stale.",
                "operation-1",
                "admin-1"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateLifecycleChangeStatus.Changed));
            Assert.That(lifecycleRepository.Transition?.ExpectedStatus, Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(lifecycleRepository.Transition?.TargetStatus, Is.EqualTo(DomainCertificateStatus.Suspended));
            Assert.That(lifecycleRepository.Transition?.ActorId, Is.EqualTo("admin-1"));
            Assert.That(lifecycleRepository.Transition?.PublicSummary, Is.EqualTo("Monitoring evidence is stale."));
            Assert.That(lifecycleRepository.Transition?.ReasonCode, Is.EqualTo("manual-suspension"));
        });
    }

    [Test]
    public async Task Missing_reason_is_rejected_before_persistence()
    {
        var lifecycleRepository = new FakeLifecycleRepository();
        var service = Service(Stored(DomainCertificateStatus.Active), lifecycleRepository);

        var result = await service.ChangeStatusAsync(
            new DomainCertificateLifecycleRequest(
                "hip-domain-cert-0001",
                DomainCertificateStatus.Revoked,
                " ",
                "operation-1",
                "admin-1"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateLifecycleChangeStatus.InvalidRequest));
            Assert.That(lifecycleRepository.Transition, Is.Null);
        });
    }

    [Test]
    public async Task Terminal_certificate_cannot_be_reinstated()
    {
        var lifecycleRepository = new FakeLifecycleRepository();
        var service = Service(Stored(DomainCertificateStatus.Revoked), lifecycleRepository);

        var result = await service.ChangeStatusAsync(
            new DomainCertificateLifecycleRequest(
                "hip-domain-cert-0001",
                DomainCertificateStatus.Active,
                "Revocation was entered in error.",
                "operation-1",
                "admin-1"),
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateLifecycleChangeStatus.Conflict));
            Assert.That(result.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Revoked));
            Assert.That(lifecycleRepository.Transition, Is.Null);
        });
    }

    private static DomainCertificateLifecycleService Service(
        HipStoredDomainCertificate stored,
        FakeLifecycleRepository lifecycleRepository) =>
        new(new FakeCertificateRepository(stored), lifecycleRepository, new FixedTimeProvider());

    private static HipStoredDomainCertificate Stored(DomainCertificateStatus status)
    {
        var certificate = CertificateTestData.SignedCertificate();
        return new HipStoredDomainCertificate(
            "enrollment-1",
            "owner-1",
            certificate,
            DomainTrustCertificateJson.Serialize(certificate),
            $"sha256:{new string('a', 64)}",
            $"sha256:{new string('b', 64)}",
            new DomainCertificateAuditEvent(
                "certificate-event-1",
                "actor-1",
                "CertificateIssued",
                null,
                DomainCertificateStatus.Active,
                null,
                "Certificate issued.",
                CertificateTestData.Now),
            status);
    }

    private sealed class FakeCertificateRepository(HipStoredDomainCertificate stored)
        : IDomainCertificateRepository
    {
        public Task<HipStoredDomainCertificate?> GetByIdAsync(
            string certificateId,
            CancellationToken cancellationToken) =>
            Task.FromResult<HipStoredDomainCertificate?>(stored);

        public Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(
            string domain,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
            HipStoredDomainCertificate certificate,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeLifecycleRepository : IDomainCertificateLifecycleRepository
    {
        public DomainCertificateStatusTransition? Transition { get; private set; }

        public Task<DomainCertificateTransitionWriteResult> TryTransitionStatusAsync(
            DomainCertificateStatusTransition transition,
            CancellationToken cancellationToken)
        {
            Transition = transition;
            return Task.FromResult(new DomainCertificateTransitionWriteResult(
                DomainCertificateTransitionWriteStatus.Updated));
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => CertificateTestData.Now.AddMinutes(5);
    }
}
