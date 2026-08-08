using HIP.Application.Certificates;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateIssuanceServiceTests
{
    [Test]
    public async Task Eligible_request_is_signed_and_committed_with_an_issuance_event()
    {
        var signed = CertificateTestData.SignedCertificate();
        var signingService = new FakeSigningService(
            new DomainCertificateSigningResult(DomainCertificateSigningStatus.Signed, signed));
        var repository = new FakeRepository();
        var service = new DomainCertificateIssuanceService(
            signingService,
            repository,
            new HIP.Application.Protocol.Rfc8785CanonicalJsonService());

        var result = await service.IssueAsync(CertificateTestData.Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateIssuanceStatus.Issued));
            Assert.That(result.Certificate, Is.EqualTo(signed));
            Assert.That(repository.Created?.IssuanceEvent.EventType, Is.EqualTo("CertificateIssued"));
            Assert.That(repository.Created?.IssuanceEvent.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(repository.Created?.SourceDecisionDigest, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(repository.Created?.CertificateDigest, Does.Match("^sha256:[0-9a-f]{64}$"));
        });
    }

    [Test]
    public async Task Managed_domain_metadata_and_issuance_snapshot_are_committed_atomically()
    {
        var signed = CertificateTestData.SignedCertificate();
        var repository = new FakeRepository();
        var service = new DomainCertificateIssuanceService(
            new FakeSigningService(new DomainCertificateSigningResult(DomainCertificateSigningStatus.Signed, signed)),
            repository,
            new HIP.Application.Protocol.Rfc8785CanonicalJsonService());
        var original = CertificateTestData.Request();
        var snapshot = new DomainCertificateIssuanceSnapshot(
            92, 90, 88, 7, "Safe", true, HIP.Domain.Domains.DomainDnssecStatus.Valid,
            "scan_1", "rules-v1", original.Draft.Evaluation.PolicyVersion, signed.Payload.IssuedAtUtc);
        var request = original with
        {
            ManagedDomainId = "domain_1",
            OrganizationId = "org_1",
            ApplicationId = "application_1",
            PublicCertificateNumber = "HIP-2026-ABCDEF123456",
            Snapshot = snapshot
        };

        var result = await service.IssueAsync(request, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateIssuanceStatus.Issued));
            Assert.That(repository.Created?.ManagedDomainId, Is.EqualTo("domain_1"));
            Assert.That(repository.Created?.ApplicationId, Is.EqualTo("application_1"));
            Assert.That(repository.Created?.PublicCertificateNumber, Is.EqualTo("HIP-2026-ABCDEF123456"));
            Assert.That(repository.Created?.Snapshot, Is.EqualTo(snapshot));
        });
    }

    [Test]
    public async Task Exact_retry_returns_existing_without_signing_again()
    {
        var signed = CertificateTestData.SignedCertificate();
        var signingService = new FakeSigningService(
            new DomainCertificateSigningResult(DomainCertificateSigningStatus.Signed, signed));
        var repository = new FakeRepository();
        var service = new DomainCertificateIssuanceService(
            signingService,
            repository,
            new HIP.Application.Protocol.Rfc8785CanonicalJsonService());
        var first = await service.IssueAsync(CertificateTestData.Request(), CancellationToken.None);
        repository.Existing = repository.Created;
        repository.Created = null;

        var retry = await service.IssueAsync(CertificateTestData.Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.Status, Is.EqualTo(DomainCertificateIssuanceStatus.Issued));
            Assert.That(retry.Status, Is.EqualTo(DomainCertificateIssuanceStatus.Existing));
            Assert.That(signingService.CallCount, Is.EqualTo(1));
            Assert.That(repository.Created, Is.Null);
        });
    }

    [TestCase(DomainCertificateSigningStatus.Ineligible, DomainCertificateIssuanceStatus.Ineligible)]
    [TestCase(DomainCertificateSigningStatus.ReviewRequired, DomainCertificateIssuanceStatus.ReviewRequired)]
    [TestCase(DomainCertificateSigningStatus.SignerUnavailable, DomainCertificateIssuanceStatus.SignerUnavailable)]
    [TestCase(DomainCertificateSigningStatus.SignerNotAuthorized, DomainCertificateIssuanceStatus.SignerNotAuthorized)]
    [TestCase(DomainCertificateSigningStatus.VerificationFailed, DomainCertificateIssuanceStatus.VerificationFailed)]
    public async Task Signing_failure_does_not_write_a_certificate(
        DomainCertificateSigningStatus signingStatus,
        DomainCertificateIssuanceStatus expectedStatus)
    {
        var signingService = new FakeSigningService(new DomainCertificateSigningResult(signingStatus));
        var repository = new FakeRepository();
        var service = new DomainCertificateIssuanceService(
            signingService,
            repository,
            new HIP.Application.Protocol.Rfc8785CanonicalJsonService());

        var result = await service.IssueAsync(CertificateTestData.Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(expectedStatus));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(repository.Created, Is.Null);
        });
    }

    private sealed class FakeSigningService(DomainCertificateSigningResult result)
        : IDomainCertificateSigningService
    {
        public int CallCount { get; private set; }

        public Task<DomainCertificateSigningResult> SignAsync(
            DomainCertificateSigningDraft draft,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(result);
        }
    }

    private sealed class FakeRepository : IDomainCertificateRepository
    {
        public HipStoredDomainCertificate? Existing { get; set; }
        public HipStoredDomainCertificate? Created { get; set; }

        public Task<HipStoredDomainCertificate?> GetByIdAsync(
            string certificateId,
            CancellationToken cancellationToken) =>
            Task.FromResult(Existing);

        public Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult(Existing);

        public Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
            HipStoredDomainCertificate certificate,
            CancellationToken cancellationToken)
        {
            Created = certificate;
            return Task.FromResult(new DomainCertificateRepositoryWriteResult(
                DomainCertificateRepositoryWriteStatus.Created,
                certificate));
        }
    }
}
