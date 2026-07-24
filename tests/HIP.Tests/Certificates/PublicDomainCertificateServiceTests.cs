using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Domain.Certificates;

namespace HIP.Tests.Certificates;

public sealed class PublicDomainCertificateServiceTests
{
    [Test]
    public async Task Verified_active_certificate_is_safe_to_present_as_active()
    {
        var stored = Stored();
        var result = await Service(stored, HipSignedDocumentVerificationStatus.Verified)
            .GetByIdAsync(stored.Certificate.Payload.CertificateId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(PublicDomainCertificateLookupStatus.Found));
            Assert.That(result.Certificate?.SignatureStatus,
                Is.EqualTo(PublicDomainCertificateSignatureStatus.Verified));
            Assert.That(result.Certificate?.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(result.Certificate?.IsActive, Is.True);
        });
    }

    [Test]
    public async Task Invalid_signature_never_presents_an_active_trust_state()
    {
        var stored = Stored();
        var result = await Service(stored, HipSignedDocumentVerificationStatus.InvalidSignature)
            .GetByIdAsync(stored.Certificate.Payload.CertificateId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(PublicDomainCertificateLookupStatus.Found));
            Assert.That(result.Certificate?.SignatureStatus,
                Is.EqualTo(PublicDomainCertificateSignatureStatus.Invalid));
            Assert.That(result.Certificate?.IsActive, Is.False);
        });
    }

    [Test]
    public async Task Expired_certificate_is_presented_as_expired_even_if_stored_status_is_active()
    {
        var stored = Stored() with
        {
            Certificate = CertificateTestData.SignedCertificate() with
            {
                Payload = CertificateTestData.SignedCertificate().Payload with
                {
                    ExpiresAtUtc = CertificateTestData.Now.AddMinutes(-1)
                }
            }
        };
        stored = stored with
        {
            SignedCertificateJson = DomainTrustCertificateJson.Serialize(stored.Certificate)
        };
        var result = await Service(stored, HipSignedDocumentVerificationStatus.Verified)
            .GetByIdAsync(stored.Certificate.Payload.CertificateId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Certificate?.CurrentStatus, Is.EqualTo(DomainCertificateStatus.Expired));
            Assert.That(result.Certificate?.IsActive, Is.False);
        });
    }

    [Test]
    public async Task Missing_certificate_returns_not_found_without_verifier_work()
    {
        var verifier = new FakeVerifier(HipSignedDocumentVerificationStatus.Verified);
        var service = new PublicDomainCertificateService(
            new FakeRepository(null),
            verifier,
            new FixedTimeProvider(CertificateTestData.Now));

        var result = await service.GetByIdAsync("hip-domain-cert-missing", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(PublicDomainCertificateLookupStatus.NotFound));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(verifier.CallCount, Is.Zero);
        });
    }

    [Test]
    public async Task Current_domain_lookup_verifies_the_same_public_certificate_contract()
    {
        var stored = Stored();
        var service = Service(stored, HipSignedDocumentVerificationStatus.Verified);

        var result = await service.GetByDomainAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(PublicDomainCertificateLookupStatus.Found));
            Assert.That(result.Certificate?.SignedCertificate.Payload.Domain, Is.EqualTo("example.com"));
            Assert.That(result.Certificate?.SignatureStatus, Is.EqualTo(PublicDomainCertificateSignatureStatus.Verified));
            Assert.That(result.Certificate?.IsActive, Is.True);
        });
    }

    private static PublicDomainCertificateService Service(
        HipStoredDomainCertificate stored,
        HipSignedDocumentVerificationStatus verificationStatus) =>
        new(
            new FakeRepository(stored),
            new FakeVerifier(verificationStatus),
            new FixedTimeProvider(CertificateTestData.Now));

    private static HipStoredDomainCertificate Stored()
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
                CertificateTestData.Now));
    }

    private sealed class FakeRepository(HipStoredDomainCertificate? stored)
        : IDomainCertificateRepository
    {
        public Task<HipStoredDomainCertificate?> GetByIdAsync(
            string certificateId,
            CancellationToken cancellationToken) =>
            Task.FromResult(stored);

        public Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(
            string domain,
            CancellationToken cancellationToken) =>
            Task.FromResult(stored);

        public Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
            HipStoredDomainCertificate certificate,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeVerifier(HipSignedDocumentVerificationStatus status)
        : IHipSignedDocumentVerifier
    {
        public int CallCount { get; private set; }

        public Task<HipSignedDocumentVerificationResult> VerifyAsync(
            HipSignedDocumentVerificationRequest request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new HipSignedDocumentVerificationResult(status));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
