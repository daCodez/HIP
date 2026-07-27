using System.Security.Cryptography;
using System.Text;
using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Application.PublicLookup;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;
using HIP.Domain.Risk;
using HIP.Tests.Certificates;

namespace HIP.Tests.PublicLookup;

[TestFixture]
public sealed class SignedLiveBadgeTests
{
    private const string IssuerId = "hip:web:badge-issuer.example";
    private const string KeyId = "badge-key-1";
    private static readonly DateTimeOffset Now = new(2026, 7, 21, 16, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Live_badge_binds_current_public_fields_and_signature_metadata_deterministically()
    {
        var verifier = new RecordingVerifier(HipSignedDocumentVerificationStatus.Verified);
        var service = CreateService(verifier: verifier);
        var request = Request();

        var first = await service.SignAsync(request, CancellationToken.None);
        var second = await service.SignAsync(request, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.Status, Is.EqualTo(HipLiveBadgeSignatureStatus.Verified));
            Assert.That(first.Document, Is.Not.Null);
            Assert.That(first.Document, Is.EqualTo(second.Document));
            Assert.That(first.Document!.Payload.DocumentType, Is.EqualTo("hip-live-badge"));
            Assert.That(first.Document.Payload.Version, Is.EqualTo("1.0"));
            Assert.That(first.Document.Payload.Domain, Is.EqualTo("example.com"));
            Assert.That(first.Document.Payload.Score, Is.EqualTo(73));
            Assert.That(first.Document.Payload.DisplayScore, Is.EqualTo(73));
            Assert.That(first.Document.Payload.ScorePresentation, Is.EqualTo(PublicEvidencePresentation.ScoreAvailable));
            Assert.That(first.Document.Payload.EvidenceCoverage, Is.EqualTo(PublicEvidencePresentation.CoverageSufficient));
            Assert.That(first.Document.Payload.EvidenceConfidence, Is.EqualTo(PublicEvidencePresentation.ConfidenceMedium));
            Assert.That(first.Document.Payload.Status, Is.EqualTo(RiskStatus.MostlyTrusted));
            Assert.That(first.Document.Payload.IdentityVerificationStatus, Is.EqualTo("Verified"));
            Assert.That(first.Document.Payload.VerifiedMeaning, Does.Contain("identity"));
            Assert.That(first.Document.Payload.Certificate?.CertificateId, Is.EqualTo("hip-domain-cert-0001"));
            Assert.That(first.Document.Payload.Certificate?.Status, Is.EqualTo(DomainCertificateStatus.Active));
            Assert.That(first.Document.Payload.Certificate?.IsActive, Is.True);
            Assert.That(first.Document.Payload.IssuedAtUtc, Is.EqualTo(Now));
            Assert.That(first.Document.Payload.ExpiresAtUtc, Is.EqualTo(Now.AddMinutes(5)));
            Assert.That(first.Document.Signature.KeyId, Is.EqualTo(KeyId));
            Assert.That(first.Document.Signature.Algorithm, Is.EqualTo("test-signature-v1"));
            Assert.That(first.EstablishesSafetyOrReputationBySignatureAlone, Is.False);
            Assert.That(verifier.Requests, Has.Count.EqualTo(2));
        });

        var signingJson = Encoding.UTF8.GetString(verifier.Requests[0].SigningPayloadJson.Span);
        Assert.Multiple(() =>
        {
            Assert.That(signingJson, Does.Contain("\"domain\":\"example.com\""));
            Assert.That(signingJson, Does.Contain("\"score\":73"));
            Assert.That(signingJson, Does.Contain("\"displayScore\":73"));
            Assert.That(signingJson, Does.Contain("\"scorePresentation\":\"Available\""));
            Assert.That(signingJson, Does.Contain("\"evidenceCoverage\":\"Sufficient\""));
            Assert.That(signingJson, Does.Contain("\"evidenceConfidence\":\"Medium\""));
            Assert.That(signingJson, Does.Contain("\"keyId\":\"badge-key-1\""));
            Assert.That(signingJson, Does.Contain("\"algorithm\":\"test-signature-v1\""));
            Assert.That(signingJson, Does.Contain("\"certificateId\":\"hip-domain-cert-0001\""));
            Assert.That(signingJson, Does.Contain("\"level\":\"Verified\""));
            Assert.That(signingJson, Does.Not.Contain("signatureValue"));
            Assert.That(signingJson, Does.Not.Contain("private-marker"));
        });
    }

    [Test]
    public async Task Changing_any_displayed_trust_field_changes_the_signed_hash()
    {
        var signer = new RecordingSigner();
        var service = CreateService(signer: signer);

        await service.SignAsync(Request(), CancellationToken.None);
        await service.SignAsync(Request() with { Score = 12, DisplayScore = 12, Status = RiskStatus.Dangerous }, CancellationToken.None);

        Assert.That(signer.Hashes, Has.Count.EqualTo(2));
        Assert.That(signer.Hashes[0], Is.Not.EqualTo(signer.Hashes[1]));
    }

    [Test]
    public async Task Unauthorized_or_revoked_signing_state_fails_closed_without_returning_a_document()
    {
        var unauthorized = CreateService(issuerPolicy: HipTrustReceiptIssuerPolicy.Default);
        var revoked = CreateService(
            verifier: new RecordingVerifier(HipSignedDocumentVerificationStatus.KeyRevoked));

        var unauthorizedResult = await unauthorized.SignAsync(Request(), CancellationToken.None);
        var revokedResult = await revoked.SignAsync(Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(unauthorizedResult.Status, Is.EqualTo(HipLiveBadgeSignatureStatus.SignerNotAuthorized));
            Assert.That(unauthorizedResult.Document, Is.Null);
            Assert.That(revokedResult.Status, Is.EqualTo(HipLiveBadgeSignatureStatus.KeyRevoked));
            Assert.That(revokedResult.Document, Is.Null);
        });
    }

    [Test]
    public async Task Verifier_rejects_expired_badges_before_using_cryptographic_state()
    {
        var recordingVerifier = new RecordingVerifier(HipSignedDocumentVerificationStatus.Verified);
        var signer = CreateService(verifier: recordingVerifier);
        var signed = await signer.SignAsync(Request(), CancellationToken.None);
        var verifier = new HipLiveBadgeVerificationService(
            recordingVerifier,
            AuthorizedIssuerPolicy(),
            HipLiveBadgePolicy.Default,
            new FixedTimeProvider(Now.AddMinutes(6)));

        var result = await verifier.VerifyAsync(signed.Document!, CancellationToken.None);

        Assert.That(result.Status, Is.EqualTo(HipLiveBadgeSignatureStatus.Expired));
        Assert.That(recordingVerifier.Requests, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task Trust_badge_marks_unsigned_runtime_data_unavailable_instead_of_showing_it_as_current()
    {
        var lookup = new StubLookupService();
        var signing = new StubBadgeSigningService(
            new HipLiveBadgeSigningResult(HipLiveBadgeSignatureStatus.SignerUnavailable));
        var service = new TrustBadgeService(lookup, signing);

        var result = await service.GetDomainBadgeAsync("Example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Domain, Is.EqualTo("example.com"));
            Assert.That(result.SignatureStatus, Is.EqualTo("SignerUnavailable"));
            Assert.That(result.SignedBadge, Is.Null);
            Assert.That(result.ResponseSignature, Is.Null);
            Assert.That(result.IsAvailable, Is.False);
        });
    }

    [Test]
    public async Task Trust_badge_projects_independently_verified_certificate_state_into_signing_request()
    {
        var signing = new StubBadgeSigningService(
            new HipLiveBadgeSigningResult(HipLiveBadgeSignatureStatus.SignerUnavailable));
        var certificate = CertificateTestData.SignedCertificate();
        var publicCertificate = new PublicDomainCertificateResponse(
            PublicDomainCertificateService.SchemaVersion,
            certificate,
            DomainCertificateStatus.Active,
            PublicDomainCertificateSignatureStatus.Verified,
            PublicDomainCertificateValidityStatus.Current,
            true,
            Now,
            certificate.Payload.RevocationStatusUrl,
            certificate.Payload.PublicCertificateUrl);
        var service = new TrustBadgeService(
            new StubLookupService(),
            signing,
            new StubPublicCertificateService(new PublicDomainCertificateLookupResult(
                PublicDomainCertificateLookupStatus.Found,
                publicCertificate)));

        var result = await service.GetDomainBadgeAsync("example.com", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Certificate?.CertificateId, Is.EqualTo(certificate.Payload.CertificateId));
            Assert.That(result.Certificate?.IsActive, Is.True);
            Assert.That(signing.Request?.Certificate, Is.EqualTo(result.Certificate));
            Assert.That(result.BadgeText, Does.Contain("Certificate: Active"));
        });
    }
    [Test]
    public void Live_badge_rejects_available_score_without_sufficient_evidence()
    {
        Assert.That(
            () => new HipLiveBadgePayload(
                HipLiveBadgePayload.LiveBadgeDocumentType,
                HipProtocolVersion.CurrentValue,
                "example.com",
                73,
                RiskStatus.MostlyTrusted,
                true,
                "Verified",
                "Identity is verified; safety remains separate.",
                Now.AddMinutes(-1),
                Now,
                Now.AddMinutes(5),
                displayScore: 73,
                scorePresentation: PublicEvidencePresentation.ScoreAvailable,
                evidenceCoverage: PublicEvidencePresentation.CoverageInsufficient,
                evidenceConfidence: PublicEvidencePresentation.ConfidenceNone),
            Throws.ArgumentException);
    }

    [Test]
    public void Active_badge_certificate_state_requires_verified_signature_and_normalized_domain()
    {
        Assert.That(
            () => new HipLiveBadgeCertificateState(
                "hip-domain-cert-0001",
                "Example.com",
                DomainCertificateLevel.Verified,
                DomainCertificateStatus.Active,
                PublicDomainCertificateSignatureStatus.Invalid,
                Now.AddDays(30),
                "https://hiptrust.com/certificate/hip-domain-cert-0001",
                true),
            Throws.ArgumentException);
    }
    private static HipLiveBadgeSigningService CreateService(
        RecordingSigner? signer = null,
        RecordingVerifier? verifier = null,
        HipTrustReceiptIssuerPolicy? issuerPolicy = null) =>
        new(
            signer ?? new RecordingSigner(),
            new Rfc8785CanonicalJsonService(),
            verifier ?? new RecordingVerifier(HipSignedDocumentVerificationStatus.Verified),
            issuerPolicy ?? AuthorizedIssuerPolicy(),
            HipLiveBadgePolicy.Default,
            new FixedTimeProvider(Now));

    private static HipLiveBadgeSigningRequest Request() => new(
        "example.com",
        73,
        RiskStatus.MostlyTrusted,
        true,
        "Verified",
        "Verified means the domain identity is known; current safety remains a separate decision.",
        Now.AddMinutes(-1),
        new HipLiveBadgeCertificateState(
            "hip-domain-cert-0001",
            "example.com",
            DomainCertificateLevel.Verified,
            DomainCertificateStatus.Active,
            PublicDomainCertificateSignatureStatus.Verified,
            Now.AddDays(30),
            "https://hiptrust.com/certificate/hip-domain-cert-0001",
            true),
        73,
        PublicEvidencePresentation.ScoreAvailable,
        PublicEvidencePresentation.CoverageSufficient,
        PublicEvidencePresentation.ConfidenceMedium);

    private static HipTrustReceiptIssuerPolicy AuthorizedIssuerPolicy() => new(
        [new HipTrustReceiptAuthorizedSigner(IssuerId, KeyId)]);

    private sealed class RecordingSigner : IManagedTrustReceiptSigner
    {
        public List<string> Hashes { get; } = [];

        public Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new HipManagedTrustReceiptSigningKey(
                IssuerId,
                KeyId,
                "test-signature-v1",
                SignatureAlgorithmFamily.Classical));

        public Task<string> SignHashAsync(
            HipManagedTrustReceiptSigningKey signingKey,
            string contentHash,
            CancellationToken cancellationToken)
        {
            Hashes.Add(contentHash);
            return Task.FromResult(Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(contentHash))));
        }
    }

    private sealed class RecordingVerifier(HipSignedDocumentVerificationStatus status) : IHipSignedDocumentVerifier
    {
        public List<HipSignedDocumentVerificationRequest> Requests { get; } = [];

        public Task<HipSignedDocumentVerificationResult> VerifyAsync(
            HipSignedDocumentVerificationRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(new HipSignedDocumentVerificationResult(status, IssuerId, KeyId));
        }
    }

    private sealed class StubLookupService : IPublicDomainLookupService
    {
        public Task<PublicDomainLookupResponse> LookupDomainAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(new PublicDomainLookupResponse(
                "example.com", 73, 73, RiskStatus.MostlyTrusted, "MostlyTrusted", "Verified",
                [], [], [], "Allow", Now.AddMinutes(-1), "Configured", "Dns", "Example Org",
                "Valid", "Verified", true, true, "/lookup/example.com", 80, 70, 68,
                "Public-safe score.", [], 1, 0, 0, 0, "BrowserPluginScan", "Current scan.")
            {
                DisplayScore = 73,
                ScorePresentation = PublicEvidencePresentation.ScoreAvailable,
                EvidenceCoverage = PublicEvidencePresentation.CoverageSufficient,
                EvidenceConfidence = PublicEvidencePresentation.ConfidenceMedium
            });
    }

    private sealed class StubBadgeSigningService(HipLiveBadgeSigningResult result) : IHipLiveBadgeSigningService
    {
        public HipLiveBadgeSigningRequest? Request { get; private set; }

        public Task<HipLiveBadgeSigningResult> SignAsync(
            HipLiveBadgeSigningRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(result);
        }
    }

    private sealed class StubPublicCertificateService(PublicDomainCertificateLookupResult result)
        : IPublicDomainCertificateService
    {
        public Task<PublicDomainCertificateLookupResult> GetByIdAsync(
            string certificateId,
            CancellationToken cancellationToken) => Task.FromResult(result);

        public Task<PublicDomainCertificateLookupResult> GetByDomainAsync(
            string domain,
            CancellationToken cancellationToken) => Task.FromResult(result);
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
