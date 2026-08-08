using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Application.SiteSafety;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateMonitoringPromotionServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Eligible_monitoring_signs_the_next_certificate_version_and_requests_atomic_persistence()
    {
        var current = CurrentCertificate();
        var certificates = new FixedCertificateRepository(current);
        var persistence = new RecordingMonitoringRepository();
        var signer = new RecordingSigner();
        var service = new DomainCertificateMonitoringPromotionService(
            certificates,
            persistence,
            signer,
            new Rfc8785CanonicalJsonService(),
            DomainCertificatePublicEndpointOptions.Default,
            ProductionAuthorityPolicy());
        var state = Enrollment();
        var scan = ScanResult();
        var check = Check();

        var result = await service.PromoteAsync(state, scan, check, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringPromotionStatus.Promoted));
            Assert.That(signer.Draft?.Level, Is.EqualTo(DomainCertificateLevel.Monitored));
            Assert.That(signer.Draft?.CertificateVersion, Is.EqualTo(2));
            Assert.That(signer.Draft?.CertificateId, Is.Not.EqualTo(current.Certificate.Payload.CertificateId));
            Assert.That(signer.Draft?.LastMonitoringAtUtc, Is.EqualTo(Now));
            Assert.That(signer.Draft?.PublicCertificateUrl, Does.EndWith($"/{signer.Draft!.CertificateId}"));
            Assert.That(persistence.Promotion?.ExpectedCertificateId,
                Is.EqualTo(current.Certificate.Payload.CertificateId));
            Assert.That(persistence.Promotion?.ExpectedCertificateVersion, Is.EqualTo(1));
            Assert.That(persistence.Promotion?.Check, Is.EqualTo(check));
            Assert.That(persistence.Promotion?.Certificate.Certificate.Payload.Level,
                Is.EqualTo(DomainCertificateLevel.Monitored));
            Assert.That(persistence.Promotion?.Certificate.Certificate.Payload.CertificateVersion, Is.EqualTo(2));
        });
    }

    [Test]
    public async Task Eligible_monitoring_reissues_monitored_certificate_from_unauthorized_legacy_signer()
    {
        var current = LegacyMonitoredCertificate();
        var certificates = new FixedCertificateRepository(current);
        var persistence = new RecordingMonitoringRepository();
        var signer = new RecordingSigner();
        var service = new DomainCertificateMonitoringPromotionService(
            certificates,
            persistence,
            signer,
            new Rfc8785CanonicalJsonService(),
            DomainCertificatePublicEndpointOptions.Default,
            ProductionAuthorityPolicy());
        var state = Enrollment() with
        {
            EnrollmentStatus = DomainEnrollmentStatus.Monitored,
            CertificateLevel = DomainCertificateLevel.Monitored
        };
        var check = Check() with { ExpectedStatus = DomainEnrollmentStatus.Monitored };

        var result = await service.PromoteAsync(state, ScanResult(), check, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringPromotionStatus.Promoted));
            Assert.That(signer.Draft?.CertificateVersion, Is.EqualTo(5));
            Assert.That(signer.Draft?.Level, Is.EqualTo(DomainCertificateLevel.Monitored));
            Assert.That(persistence.Promotion?.ExpectedCertificateId,
                Is.EqualTo(current.Certificate.Payload.CertificateId));
        });
    }

    [Test]
    public async Task Eligible_monitoring_reissues_authorized_certificate_with_obsolete_public_origin()
    {
        var legacy = LegacyMonitoredCertificate();
        var certificate = legacy.Certificate with
        {
            Signature = legacy.Certificate.Signature with
            {
                AuthorityId = "hip:service:domain-certificate-authority",
                KeyId = "certificate-key-1"
            }
        };
        var current = legacy with
        {
            Certificate = certificate,
            SignedCertificateJson = DomainTrustCertificateJson.Serialize(certificate)
        };
        var persistence = new RecordingMonitoringRepository();
        var signer = new RecordingSigner();
        var service = new DomainCertificateMonitoringPromotionService(
            new FixedCertificateRepository(current),
            persistence,
            signer,
            new Rfc8785CanonicalJsonService(),
            DomainCertificatePublicEndpointOptions.Default,
            ProductionAuthorityPolicy());
        var state = Enrollment() with
        {
            EnrollmentStatus = DomainEnrollmentStatus.Monitored,
            CertificateLevel = DomainCertificateLevel.Monitored
        };
        var check = Check() with { ExpectedStatus = DomainEnrollmentStatus.Monitored };

        var result = await service.PromoteAsync(state, ScanResult(), check, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateMonitoringPromotionStatus.Promoted));
            Assert.That(signer.Draft?.PublicCertificateUrl, Does.StartWith("https://guardwithhip.com/"));
            Assert.That(signer.Draft?.RevocationStatusUrl,
                Does.StartWith("https://guardwithhip.com/api/v1/public/certificates/"));
        });
    }

    private static DomainMonitoringEnrollmentState Enrollment() => new(
        "enrollment-1",
        "owner-1",
        "example.com",
        DomainEnrollmentStatus.Verified,
        DomainCertificateStatus.Active,
        DomainCertificateLevel.Verified,
        Now.AddDays(-2),
        Now.AddDays(-2),
        Now.AddDays(-1),
        Now.AddHours(-1),
        null,
        78);

    private static DomainMonitoringCheckRecord Check() => new(
        "enrollment-1",
        "owner-1",
        "example.com",
        DomainEnrollmentStatus.Verified,
        DomainEnrollmentStatus.Monitored,
        82,
        0,
        Now,
        Now.AddHours(24),
        $"sha256:{new string('e', 64)}",
        "certificate-event:monitoring-check:promotion");

    private static DomainCertificateSecurityScanResult ScanResult()
    {
        var evaluation = new DomainCertificatePolicyEvaluationResult(
            "example.com",
            DomainCertificateLevel.Monitored,
            DomainCertificatePolicy.V1.Version,
            DomainCertificatePolicyDecision.Eligible,
            "This domain is verified and continuously monitored by HIP.",
            [],
            Now);
        var scan = new SiteSafetyScanResult(
            "scan-1", "https://example.com/", "example.com", Now,
            0, 0, 0, 0, 0, 0, 0, 0,
            SiteSafetyScanStatus.Clean,
            "Clean monitoring scan.",
            ["No critical findings."],
            [], [], [],
            "High",
            82, 82, 82, 82,
            [],
            new SiteSafetyScoreImpact(82, 82, 82, 82, []));
        return new DomainCertificateSecurityScanResult(
            DomainCertificateSecurityScanStatus.Evaluated,
            scan,
            evaluation,
            DomainCertificatePublicRiskClassification.Low,
            []);
    }

    private static HipStoredDomainCertificate CurrentCertificate()
    {
        var certificate = CertificateTestData.SignedCertificate();
        var json = DomainTrustCertificateJson.Serialize(certificate);
        return new HipStoredDomainCertificate(
            "enrollment-1",
            "owner-1",
            certificate,
            json,
            $"sha256:{new string('a', 64)}",
            $"sha256:{new string('b', 64)}",
            new DomainCertificateAuditEvent(
                "certificate-event-current",
                "owner-1",
                "CertificateIssued",
                null,
                DomainCertificateStatus.Active,
                null,
                "HIP issued the verified certificate.",
                certificate.Payload.IssuedAtUtc));
    }

    private static HipStoredDomainCertificate LegacyMonitoredCertificate()
    {
        var current = CurrentCertificate();
        var certificate = current.Certificate with
        {
            Payload = current.Certificate.Payload with
            {
                CertificateId = "hip-domain-cert-legacy-v4",
                CertificateVersion = 4,
                Level = DomainCertificateLevel.Monitored,
                LastMonitoringAtUtc = Now.AddHours(-1)
            },
            Signature = current.Certificate.Signature with
            {
                AuthorityId = "hip:development:web-certificate-authority",
                KeyId = "development-legacy-key"
            }
        };
        return current with
        {
            Certificate = certificate,
            SignedCertificateJson = DomainTrustCertificateJson.Serialize(certificate)
        };
    }

    private static DomainCertificateSigningAuthorityPolicy ProductionAuthorityPolicy() =>
        new([
            new DomainCertificateAuthorizedSigner(
                "hip:service:domain-certificate-authority",
                "certificate-key-1")
        ]);

    private sealed class FixedCertificateRepository(HipStoredDomainCertificate current)
        : IDomainCertificateRepository
    {
        public Task<HipStoredDomainCertificate?> GetByIdAsync(string certificateId, CancellationToken cancellationToken) =>
            Task.FromResult<HipStoredDomainCertificate?>(
                certificateId == current.Certificate.Payload.CertificateId ? current : null);

        public Task<HipStoredDomainCertificate?> GetCurrentByDomainAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult<HipStoredDomainCertificate?>(domain == current.Certificate.Payload.Domain ? current : null);

        public Task<DomainCertificateRepositoryWriteResult> TryCreateIssuedAsync(
            HipStoredDomainCertificate certificate,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingMonitoringRepository : IDomainCertificateMonitoringRepository
    {
        public DomainMonitoringCertificatePromotionRecord? Promotion { get; private set; }

        public Task<DomainMonitoringWriteStatus> TryApplyPromotedCheckAsync(
            DomainMonitoringCertificatePromotionRecord promotion,
            CancellationToken cancellationToken)
        {
            Promotion = promotion;
            return Task.FromResult(DomainMonitoringWriteStatus.Updated);
        }

        public Task<DomainMonitoringEnrollmentState?> GetForMonitoringAsync(string ownerId, string domain, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainMonitoringWriteStatus> TryEnableAsync(DomainMonitoringEnableRecord record, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DomainMonitoringWriteStatus> TryApplyCheckAsync(DomainMonitoringCheckRecord record, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class RecordingSigner : IDomainCertificateSigningService
    {
        public DomainCertificateSigningDraft? Draft { get; private set; }

        public Task<DomainCertificateSigningResult> SignAsync(
            DomainCertificateSigningDraft draft,
            CancellationToken cancellationToken)
        {
            Draft = draft;
            var payload = new DomainTrustCertificatePayload(
                draft.CertificateId, draft.CertificateVersion, draft.Evaluation.PolicyVersion,
                draft.Domain, draft.PublicDisplayName, draft.PublicOrganizationName, draft.Level,
                DomainCertificateStatus.Active, Now, Now.AddDays(365), draft.LastVerificationAtUtc,
                draft.LastMonitoringAtUtc, draft.RegistrantPublicKeyId, draft.CompletedVerificationMethods,
                draft.PublicRiskClassification, draft.PublicFindingCodes, draft.RevocationStatusUrl,
                draft.PublicCertificateUrl);
            var signature = new DomainTrustCertificateSignature(
                "hip:service:domain-certificate-authority", "certificate-key-1", "test-signature-v1",
                SignatureAlgorithmFamily.Unknown, HipProtocolSignature.Rfc8785Canonicalization, "signature");
            return Task.FromResult(new DomainCertificateSigningResult(
                DomainCertificateSigningStatus.Signed,
                new SignedDomainTrustCertificate(payload, signature)));
        }
    }
}
