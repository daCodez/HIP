using HIP.Application.Certificates;
using HIP.Application.Protocol;
using HIP.Domain.Certificates;
using HIP.Domain.Identity;
using HIP.Domain.Protocol;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateSigningServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 24, 14, 0, 0, TimeSpan.Zero);
    private const string AuthorityId = "hip:service:domain-certificate-authority";
    private const string KeyId = "certificate-key-1";

    [Test]
    public async Task Eligible_certificate_is_canonicalized_signed_and_self_verified()
    {
        var signer = new FakeManagedSigner();
        var verifier = new FakeSignedDocumentVerifier(HipSignedDocumentVerificationStatus.Verified);
        var result = await Service(signer, verifier).SignAsync(Draft(
            methods: [VerificationMethod.WellKnownHipJson, VerificationMethod.DnsTxt, VerificationMethod.DnsTxt],
            findingCodes: ["tls.valid", "scan.no-critical", "tls.valid"]), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.Signed));
            Assert.That(result.Certificate, Is.Not.Null);
            Assert.That(result.Certificate!.Payload.IssuedAtUtc, Is.EqualTo(Now));
            Assert.That(result.Certificate.Payload.ExpiresAtUtc, Is.EqualTo(Now.Add(DomainCertificatePolicy.V1.VerifiedLifetime)));
            Assert.That(result.Certificate.Payload.CompletedVerificationMethods,
                Is.EqualTo(new[] { VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson }));
            Assert.That(result.Certificate.Payload.PublicFindingCodes,
                Is.EqualTo(new[] { "scan.no-critical", "tls.valid" }));
            Assert.That(result.Certificate.Signature.AuthorityId, Is.EqualTo(AuthorityId));
            Assert.That(result.Certificate.Signature.KeyId, Is.EqualTo(KeyId));
            Assert.That(signer.SignCount, Is.EqualTo(1));
            Assert.That(signer.LastContentHash, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(verifier.LastRequest?.IssuerId, Is.EqualTo(AuthorityId));
            Assert.That(verifier.LastRequest?.KeyId, Is.EqualTo(KeyId));
        });
    }

    [TestCase(DomainCertificatePolicyDecision.Ineligible, DomainCertificateSigningStatus.Ineligible)]
    [TestCase(DomainCertificatePolicyDecision.RequiresReview, DomainCertificateSigningStatus.ReviewRequired)]
    public async Task Non_eligible_policy_decision_never_reaches_key_custody(
        DomainCertificatePolicyDecision decision,
        DomainCertificateSigningStatus expected)
    {
        var signer = new FakeManagedSigner();
        var result = await Service(signer, Verified()).SignAsync(
            Draft() with { Evaluation = Evaluation(decision) }, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(expected));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(signer.GetKeyCount, Is.Zero);
            Assert.That(signer.SignCount, Is.Zero);
        });
    }

    [Test]
    public async Task Authorized_manual_review_allows_a_review_required_certificate_to_be_signed()
    {
        var signer = new FakeManagedSigner();
        var draft = Draft() with
        {
            Evaluation = Evaluation(DomainCertificatePolicyDecision.RequiresReview),
            AuthorizedReview = new DomainCertificateAuthorizedReview(
                "domain-application_123", "admin-reviewer", Now.AddMinutes(-2), "Approved")
        };

        var result = await Service(signer, Verified()).SignAsync(draft, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.Signed));
            Assert.That(result.Certificate, Is.Not.Null);
            Assert.That(signer.SignCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Invalid_manual_review_metadata_is_rejected_before_key_custody()
    {
        var signer = new FakeManagedSigner();
        var draft = Draft() with
        {
            Evaluation = Evaluation(DomainCertificatePolicyDecision.RequiresReview),
            AuthorizedReview = new DomainCertificateAuthorizedReview(
                "domain-application_123", "admin-reviewer", Now.AddMinutes(1), "Approved")
        };

        var result = await Service(signer, Verified()).SignAsync(draft, default);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.InvalidRequest));
            Assert.That(signer.GetKeyCount, Is.Zero);
        });
    }

    [Test]
    public async Task Unapproved_certificate_authority_key_cannot_sign()
    {
        var signer = new FakeManagedSigner();
        var result = await Service(signer, Verified(), new DomainCertificateSigningAuthorityPolicy([]))
            .SignAsync(Draft(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.SignerNotAuthorized));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(signer.GetKeyCount, Is.EqualTo(1));
            Assert.That(signer.SignCount, Is.Zero);
        });
    }

    [Test]
    public async Task Failed_signature_self_verification_returns_no_certificate()
    {
        var signer = new FakeManagedSigner();
        var result = await Service(signer, new FakeSignedDocumentVerifier(HipSignedDocumentVerificationStatus.InvalidSignature))
            .SignAsync(Draft(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.VerificationFailed));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(signer.SignCount, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task Equivalent_public_collection_order_produces_identical_signed_json()
    {
        var first = await Service(new FakeManagedSigner(), Verified()).SignAsync(
            Draft(methods: [VerificationMethod.WellKnownHipJson, VerificationMethod.DnsTxt],
                findingCodes: ["tls.valid", "scan.no-critical"]), CancellationToken.None);
        var second = await Service(new FakeManagedSigner(), Verified()).SignAsync(
            Draft(methods: [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
                findingCodes: ["scan.no-critical", "tls.valid"]), CancellationToken.None);

        Assert.That(DomainTrustCertificateJson.Serialize(second.Certificate!),
            Is.EqualTo(DomainTrustCertificateJson.Serialize(first.Certificate!)));
    }

    [TestCase("finding-code")]
    [TestCase("certificate-url")]
    public async Task Privacy_unsafe_public_data_is_rejected_before_key_custody(string field)
    {
        var signer = new FakeManagedSigner();
        var draft = field == "finding-code"
            ? Draft(findingCodes: ["contact:user@example.com"])
            : Draft() with
            {
                PublicCertificateUrl = "https://hiptrust.com/certificate/hip-domain-cert-0001?token=secret"
            };

        var result = await Service(signer, Verified()).SignAsync(draft, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSigningStatus.InvalidRequest));
            Assert.That(result.Certificate, Is.Null);
            Assert.That(signer.GetKeyCount, Is.Zero);
            Assert.That(signer.SignCount, Is.Zero);
        });
    }

    [Test]
    public async Task Public_json_uses_stable_named_enum_values()
    {
        var result = await Service(new FakeManagedSigner(), Verified())
            .SignAsync(Draft(), CancellationToken.None);

        var json = DomainTrustCertificateJson.Serialize(result.Certificate!);

        Assert.Multiple(() =>
        {
            Assert.That(json, Does.Contain("\"level\":\"Verified\""));
            Assert.That(json, Does.Contain("\"status\":\"Active\""));
            Assert.That(json, Does.Contain("\"publicRiskClassification\":\"Low\""));
        });
    }

    private static DomainCertificateSigningService Service(
        FakeManagedSigner signer,
        FakeSignedDocumentVerifier verifier,
        DomainCertificateSigningAuthorityPolicy? authorityPolicy = null) =>
        new(signer, verifier, new Rfc8785CanonicalJsonService(), DomainCertificatePolicy.V1,
            authorityPolicy ?? new DomainCertificateSigningAuthorityPolicy(
                [new DomainCertificateAuthorizedSigner(AuthorityId, KeyId)]),
            new FixedTimeProvider(Now));

    private static FakeSignedDocumentVerifier Verified() =>
        new(HipSignedDocumentVerificationStatus.Verified);

    private static DomainCertificateSigningDraft Draft(
        IReadOnlyCollection<VerificationMethod>? methods = null,
        IReadOnlyCollection<string>? findingCodes = null) =>
        new(
            "hip-domain-cert-0001",
            1,
            "example.com",
            DomainCertificateLevel.Verified,
            "Example Site",
            "Example Organization",
            "registrant-key-1",
            methods ?? [VerificationMethod.DnsTxt, VerificationMethod.WellKnownHipJson],
            DomainCertificatePublicRiskClassification.Low,
            findingCodes ?? ["scan.no-critical", "tls.valid"],
            "https://hiptrust.com/api/v1/certificates/hip-domain-cert-0001/status",
            "https://hiptrust.com/certificate/hip-domain-cert-0001",
            Now.AddMinutes(-10),
            null,
            Evaluation(DomainCertificatePolicyDecision.Eligible));

    private static DomainCertificatePolicyEvaluationResult Evaluation(
        DomainCertificatePolicyDecision decision) =>
        new(
            "example.com",
            DomainCertificateLevel.Verified,
            DomainCertificatePolicy.V1.Version,
            decision,
            "This domain completed HIP identity and baseline security verification.",
            [],
            Now.AddMinutes(-1));

    private sealed class FakeManagedSigner : IManagedTrustReceiptSigner
    {
        public int GetKeyCount { get; private set; }
        public int SignCount { get; private set; }
        public string? LastContentHash { get; private set; }

        public Task<HipManagedTrustReceiptSigningKey> GetSigningKeyAsync(CancellationToken cancellationToken)
        {
            GetKeyCount++;
            return Task.FromResult(new HipManagedTrustReceiptSigningKey(
                AuthorityId,
                KeyId,
                "test-signature-v1",
                SignatureAlgorithmFamily.Unknown));
        }

        public Task<string> SignHashAsync(
            HipManagedTrustReceiptSigningKey signingKey,
            string contentHash,
            CancellationToken cancellationToken)
        {
            SignCount++;
            LastContentHash = contentHash;
            return Task.FromResult($"signature:{contentHash}");
        }
    }

    private sealed class FakeSignedDocumentVerifier(HipSignedDocumentVerificationStatus status)
        : IHipSignedDocumentVerifier
    {
        public HipSignedDocumentVerificationRequest? LastRequest { get; private set; }

        public Task<HipSignedDocumentVerificationResult> VerifyAsync(
            HipSignedDocumentVerificationRequest request,
            CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(new HipSignedDocumentVerificationResult(
                status,
                status == HipSignedDocumentVerificationStatus.Verified ? request.IssuerId : null,
                status == HipSignedDocumentVerificationStatus.Verified ? request.KeyId : null));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
