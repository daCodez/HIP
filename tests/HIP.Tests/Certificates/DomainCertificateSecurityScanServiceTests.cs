using HIP.Application.Browser;
using HIP.Application.Certificates;
using HIP.Application.SiteSafety;
using HIP.Domain.Certificates;
using HIP.Domain.Scoring;

namespace HIP.Tests.Certificates;

public sealed class DomainCertificateSecurityScanServiceTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task Fixed_https_origin_with_authoritative_tls_evidence_is_stored_and_eligible()
    {
        var scanner = new RecordingScanner(Result(
            SiteSafetyScanStatus.LimitedData,
            [TlsEvidence()]));
        var writer = new RecordingWriter();
        var service = Service(scanner, writer);

        var result = await service.ScanAsync(Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(scanner.Request?.Url, Is.EqualTo("https://example.com/"));
            Assert.That(scanner.Request?.ObservedSignals, Is.Null);
            Assert.That(result.Status, Is.EqualTo(DomainCertificateSecurityScanStatus.Evaluated));
            Assert.That(result.Evaluation?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Eligible));
            Assert.That(result.PublicRiskClassification, Is.EqualTo(DomainCertificatePublicRiskClassification.Low));
            Assert.That(writer.Request, Is.Not.Null);
            Assert.That(writer.Request!.PageUrl, Is.Null);
            Assert.That(writer.Request.PageUrlHash, Does.Match("^sha256:[0-9a-f]{64}$"));
            Assert.That(writer.Request.PrivacySafeMetadata?["scanPurpose"],
                Is.EqualTo("DomainCertificateSecurityReview"));
        });
    }

    [Test]
    public async Task Missing_verified_account_contact_fails_closed_after_scan()
    {
        var service = Service(
            new RecordingScanner(Result(SiteSafetyScanStatus.Clean, [TlsEvidence()])),
            new RecordingWriter());

        var result = await service.ScanAsync(
            Request() with { AccountContactVerified = false },
            CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Evaluation?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
            Assert.That(result.Evaluation?.Requirements, Has.Some.Matches<DomainCertificateRequirementResult>(
                item => item.Code == "account.contact" &&
                        item.Status == DomainCertificateRequirementStatus.Missing));
        });
    }

    [Test]
    public async Task Dangerous_authoritative_finding_is_publicly_coded_and_blocks_issuance()
    {
        var dangerous = new SiteSafetyEvidence(
            "Threat Test",
            SiteSafetyEvidenceProviderType.ThreatIntel,
            SiteSafetyEvidenceTargetType.Domain,
            "example.com",
            null,
            [new SiteSafetyEvidenceItem(
                "Phishing Match",
                "Hit",
                SiteSafetyEvidenceStatus.Dangerous,
                100,
                0,
                "A phishing signal matched.",
                EvidenceType: "ThreatMatch",
                Confidence: 95,
                Severity: SiteSafetyEvidenceSeverity.Critical,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                IsNegativeSignal: true,
                IsBlockingSignal: true)],
            95,
            Now,
            Now.AddHours(1),
            [],
            IsAuthoritativeForRisk: true,
            IsAuthoritativeForTrust: false);
        var service = Service(
            new RecordingScanner(Result(SiteSafetyScanStatus.Dangerous, [TlsEvidence(), dangerous])),
            new RecordingWriter());

        var result = await service.ScanAsync(Request(), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Evaluation?.Decision, Is.EqualTo(DomainCertificatePolicyDecision.Ineligible));
            Assert.That(result.PublicRiskClassification,
                Is.EqualTo(DomainCertificatePublicRiskClassification.Critical));
            Assert.That(result.PublicFindingCodes, Does.Contain("phishing-match"));
            Assert.That(result.Evaluation?.Requirements, Has.Some.Matches<DomainCertificateRequirementResult>(
                item => item.Code == "security.no-critical-findings" &&
                        item.Status == DomainCertificateRequirementStatus.Missing));
        });
    }

    private static DomainCertificateSecurityScanService Service(
        ISiteSafetyScanner scanner,
        IBrowserScanResultWriteService writer) =>
        new(
            scanner,
            writer,
            new DomainCertificatePolicyEvaluator(DomainCertificatePolicy.V1),
            new ExternalSiteEvidenceOptions(),
            new FixedTimeProvider(Now));

    private static DomainCertificateSecurityScanRequest Request() =>
        new(
            "example.com",
            DomainCertificateLevel.Verified,
            AccountContactVerified: true,
            DomainControlVerifiedAtUtc: Now.AddHours(-1),
            DnsVerifiedAtUtc: Now.AddHours(-1),
            WebsiteVerifiedAtUtc: Now.AddMinutes(-30),
            IdentityInformationCompleted: true);

    private static SiteSafetyScanResult Result(
        SiteSafetyScanStatus status,
        IReadOnlyCollection<SiteSafetyEvidence> evidence) =>
        new(
            "certificate-scan-1",
            "https://example.com/",
            "example.com",
            Now.AddMinutes(-1),
            0, 0, 0, 0, 0, 0, 0,
            status is SiteSafetyScanStatus.Dangerous ? 100 : 0,
            status,
            "Server-owned certificate scan.",
            ["HIP completed the fixed-origin scan."],
            [],
            [],
            [],
            "High",
            80,
            80,
            90,
            status is SiteSafetyScanStatus.Dangerous ? 5 : 85,
            evidence,
            new SiteSafetyScoreImpact(80, 80, 90, 85, Array.Empty<ScoreComponent>()));

    private static SiteSafetyEvidence TlsEvidence() =>
        new(
            "TLS Test",
            SiteSafetyEvidenceProviderType.TlsScanner,
            SiteSafetyEvidenceTargetType.Domain,
            "example.com",
            null,
            [new SiteSafetyEvidenceItem(
                "TlsGrade",
                "A",
                SiteSafetyEvidenceStatus.Positive,
                0,
                10,
                "TLS configuration is strong.",
                EvidenceType: "TlsGrade",
                Confidence: 90,
                Severity: SiteSafetyEvidenceSeverity.Info,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                IsPositiveSignal: true)],
            90,
            Now,
            Now.AddHours(1),
            [],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: true);

    private sealed class RecordingScanner(SiteSafetyScanResult result) : ISiteSafetyScanner
    {
        public SiteSafetyScanRequest? Request { get; private set; }

        public Task<SiteSafetyScanResult> ScanAsync(
            SiteSafetyScanRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(result);
        }
    }

    private sealed class RecordingWriter : IBrowserScanResultWriteService
    {
        public BrowserScanResultSaveRequest? Request { get; private set; }

        public Task<BrowserScanResultSaveResponse> SaveAsync(
            BrowserScanResultSaveRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new BrowserScanResultSaveResponse(
                true,
                request.Domain,
                request.ScannedAtUtc ?? Now));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
