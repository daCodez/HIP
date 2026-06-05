using FluentValidation;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.SiteSafety;

namespace HIP.Tests.Review;

/// <summary>
/// Tests the privacy-safe admin review queue that receives generated safety, provider, and feedback signals.
/// </summary>
[TestFixture]
public sealed class AdminReviewQueueSignalTests
{
    /// <summary>
    /// High-risk scans with low confidence create review items instead of silently changing trust.
    /// </summary>
    [Test]
    public async Task High_risk_low_confidence_scan_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromScanAsync(Scan(Status: SiteSafetyScanStatus.HighRisk, Confidence: "Low"), CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("HighRiskLowConfidence"));
    }

    /// <summary>
    /// Conflicting provider evidence creates a human review signal.
    /// </summary>
    [Test]
    public async Task Conflicting_external_provider_evidence_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromScanAsync(Scan(MatchedRules: [Rule("external-conflict")]), CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("ConflictingProviderEvidence"));
    }

    /// <summary>
    /// Unknown or limited-data login pages are queued for review because login forms raise abuse impact.
    /// </summary>
    [Test]
    public async Task Unknown_domain_login_form_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromScanAsync(Scan(
            Status: SiteSafetyScanStatus.LimitedData,
            FormRisk: 45,
            Warnings: ["Login fields were detected on a limited-data domain."]), CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("UnknownDomainLoginForm"));
    }

    /// <summary>
    /// Payment fields on low-trust pages are treated as higher severity review signals.
    /// </summary>
    [Test]
    public async Task Unknown_payment_field_creates_high_severity_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromScanAsync(Scan(
            Status: SiteSafetyScanStatus.LimitedData,
            Warnings: ["Payment fields were detected on a limited-data domain."]), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(items.Single().ReviewReason, Is.EqualTo("UnknownDomainPaymentField"));
            Assert.That(items.Single().Severity, Is.EqualTo(AdminReviewSeverity.High));
        });
    }

    /// <summary>
    /// Repeated or suspicious feedback patterns become review evidence instead of raw popularity votes.
    /// </summary>
    [Test]
    public async Task Repeated_suspicious_feedback_creates_review_signal()
    {
        var service = CreateService();
        var summary = new WeightedFeedbackSummary(
            "feedback.example",
            LooksSafeWeight: 0,
            LooksSuspiciousWeight: 12,
            ReportIssueWeight: 4,
            RecentFeedbackCount: 8,
            RepeatedReporterCount: 3,
            SuspiciousFeedbackPattern: true,
            ConflictingFeedbackSpike: false,
            ConfidenceImpact: 20,
            RecommendedReview: true,
            ["Recent feedback patterns may be repetitive or low-quality."]);

        var items = await service.CreateSignalsFromFeedbackAsync(summary, CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("WeightedFeedbackReview"));
    }

    /// <summary>
    /// Trusted parent domains with risky page or content signals are reviewed because domain trust does not make every page safe.
    /// </summary>
    [Test]
    public async Task Trusted_domain_with_risky_content_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromScanAsync(Scan(
            DomainTrust: 92,
            PageTrust: 35,
            ContentRisk: 42,
            DownloadRisk: 55), CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("TrustedDomainRiskyPageContent"));
    }

    /// <summary>
    /// Review items preserve domain and URL hash while avoiding raw page URLs.
    /// </summary>
    [Test]
    public async Task Review_signal_stores_domain_and_url_hash()
    {
        var service = CreateService();

        var item = (await service.CreateSignalsFromScanAsync(Scan(
            Status: SiteSafetyScanStatus.HighRisk,
            Confidence: "Low",
            ProviderEvidence: [Evidence("sha256:page")]), CancellationToken.None)).Single();

        Assert.Multiple(() =>
        {
            Assert.That(item.Domain, Is.EqualTo("example.com"));
            Assert.That(item.UrlHash, Is.EqualTo("sha256:page"));
            Assert.That(item.EvidenceSummary, Does.Not.Contain("https://"));
        });
    }

    /// <summary>
    /// Obvious raw page-text markers are redacted before review records are saved.
    /// </summary>
    [Test]
    public async Task Review_signal_does_not_store_page_text()
    {
        var service = CreateService();

        var item = await service.CreateSignalAsync(Signal(Summary: "raw page text should not be stored"), CancellationToken.None);

        Assert.That(item.Summary, Is.EqualTo("[privacy-safe review summary redacted]"));
    }

    /// <summary>
    /// Obvious form-value markers are redacted before review records are saved.
    /// </summary>
    [Test]
    public async Task Review_signal_does_not_store_form_values()
    {
        var service = CreateService();

        var item = await service.CreateSignalAsync(Signal(EvidenceSummary: "form value should not be stored"), CancellationToken.None);

        Assert.That(item.EvidenceSummary, Is.EqualTo("[privacy-safe review summary redacted]"));
    }

    /// <summary>
    /// Assignment moves an open review item into InReview.
    /// </summary>
    [Test]
    public async Task Assigning_review_item_moves_status_to_in_review()
    {
        var service = CreateService();
        var item = await service.CreateSignalAsync(Signal(), CancellationToken.None);

        var updated = await service.AssignAsync(item.ReviewId, "moderator-1", "admin-1", CancellationToken.None);

        Assert.That(updated.Status, Is.EqualTo(AdminReviewStatus.InReview));
    }

    /// <summary>
    /// Admin decisions are stored as evidence and do not directly override scoring.
    /// </summary>
    [Test]
    public async Task Admin_decision_is_recorded_as_review_evidence()
    {
        var service = CreateService();
        var item = await service.CreateSignalAsync(Signal(), CancellationToken.None);

        var updated = await service.RecordDecisionAsync(item.ReviewId, new HIP.Application.Review.AdminReviewDecisionRequest(
            AdminReviewDecision.ConfirmSuspicious,
            "Privacy-safe evidence supports a suspicious label.",
            "moderator-1"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(updated.Status, Is.EqualTo(AdminReviewStatus.Resolved));
            Assert.That(updated.Decision, Is.EqualTo(AdminReviewDecision.ConfirmSuspicious));
        });
    }

    /// <summary>
    /// Dismissal preserves evidence summaries for auditability and later investigation.
    /// </summary>
    [Test]
    public async Task Dismissed_review_keeps_privacy_safe_evidence()
    {
        var service = CreateService();
        var item = await service.CreateSignalAsync(Signal(EvidenceSummary: "URL hash and domain-level provider mismatch."), CancellationToken.None);

        var updated = await service.DismissAsync(item.ReviewId, "moderator-1", "No action needed.", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(updated.Status, Is.EqualTo(AdminReviewStatus.Dismissed));
            Assert.That(updated.EvidenceSummary, Is.EqualTo("URL hash and domain-level provider mismatch."));
        });
    }

    /// <summary>
    /// Audit entries for review decisions redact obvious private-content markers.
    /// </summary>
    [Test]
    public async Task Admin_decision_creates_safe_audit_log()
    {
        var audit = new AuditLogService();
        var service = CreateService(audit);
        var item = await service.CreateSignalAsync(Signal(), CancellationToken.None);

        await service.RecordDecisionAsync(item.ReviewId, new HIP.Application.Review.AdminReviewDecisionRequest(
            AdminReviewDecision.FalsePositive,
            "raw private message should not be stored",
            "moderator-1"), CancellationToken.None);

        Assert.That(audit.List().Select(entry => entry.Summary), Has.Some.EqualTo("[privacy-safe review summary redacted]"));
    }

    /// <summary>
    /// Duplicate open signals reuse the existing review item to reduce queue noise.
    /// </summary>
    [Test]
    public async Task Duplicate_open_review_signal_is_deduplicated()
    {
        var service = CreateService();

        var first = await service.CreateSignalAsync(Signal(), CancellationToken.None);
        var second = await service.CreateSignalAsync(Signal(), CancellationToken.None);
        var items = await service.ListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(second.ReviewId, Is.EqualTo(first.ReviewId));
            Assert.That(items, Has.Count.EqualTo(1));
        });
    }

    /// <summary>
    /// Creates a review queue service with an in-memory repository for focused domain tests.
    /// </summary>
    private static AdminReviewQueueService CreateService(AuditLogService? auditLogService = null) =>
        new(
            new InMemoryAdminReviewQueueRepository(),
            new AdminReviewQueueItemValidator(),
            auditLogService ?? new AuditLogService());

    /// <summary>
    /// Builds a minimal privacy-safe scan result for review signal tests.
    /// </summary>
    private static SiteSafetyScanResult Scan(
        SiteSafetyScanStatus Status = SiteSafetyScanStatus.LimitedData,
        string Confidence = "Medium",
        int DomainTrust = 55,
        int PageTrust = 55,
        int ContentRisk = 65,
        int DownloadRisk = 0,
        int FormRisk = 0,
        IReadOnlyCollection<string>? Warnings = null,
        IReadOnlyCollection<SiteSafetyRuleResult>? MatchedRules = null,
        IReadOnlyCollection<SiteSafetyEvidence>? ProviderEvidence = null) =>
        new(
            "scan-test",
            "https://example.com/page",
            "example.com",
            DateTimeOffset.UtcNow,
            MalwareRiskScore: 0,
            PhishingRiskScore: 0,
            RedirectRiskScore: 0,
            ScriptRiskScore: 0,
            DownloadRisk,
            FormRisk,
            ReputationRiskScore: 0,
            OverallSafetyRiskScore: Status is SiteSafetyScanStatus.HighRisk ? 75 : 10,
            Status,
            "Privacy-safe scan summary.",
            ["Domain-level and URL-hash evidence only."],
            Warnings ?? [],
            [],
            [],
            Confidence,
            DomainTrust,
            PageTrust,
            ContentRisk,
            FinalHipScore: Status is SiteSafetyScanStatus.HighRisk ? 22 : 56,
            ProviderEvidence ?? [],
            new SiteSafetyScoreImpact(DomainTrust, PageTrust, ContentRisk, 56, []),
            MatchedRules);

    /// <summary>
    /// Builds a minimal rule result used to trigger review signal paths.
    /// </summary>
    private static SiteSafetyRuleResult Rule(string ruleId) =>
        new(
            ruleId,
            "External conflict",
            "Provider evidence conflicts.",
            SiteSafetyRuleSource.BuiltIn,
            SiteSafetyRuleCollectionType.ExternalEvidenceRules,
            SiteSafetyRiskCategory.Reputation,
            RiskImpact: 0,
            TrustImpact: 0,
            "External evidence conflicts.",
            "Conflicting provider evidence should be reviewed.",
            SiteSafetyRuleSeverity.High,
            SiteSafetyEvidenceQuality.Medium,
            null,
            ConfidencePenalty: 20,
            SendToAdminReview: true,
            IsSimulationOnly: false);

    /// <summary>
    /// Builds provider evidence with a URL hash and no raw URL.
    /// </summary>
    private static SiteSafetyEvidence Evidence(string urlHash) =>
        new(
            "Test Provider",
            SiteSafetyEvidenceProviderType.HipHistory,
            SiteSafetyEvidenceTargetType.Url,
            "example.com",
            urlHash,
            [],
            60,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            [],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);

    /// <summary>
    /// Builds a minimal review signal for direct service tests.
    /// </summary>
    private static AdminReviewSignal Signal(string Summary = "Privacy-safe review signal.", string EvidenceSummary = "Domain-level evidence only.") =>
        new(
            "example.com",
            "sha256:page",
            AdminReviewTargetType.Domain,
            "PossibleFalsePositive",
            AdminReviewSeverity.Medium,
            AdminReviewSource.System,
            null,
            null,
            null,
            56,
            "LimitedTrustData",
            "Medium",
            Summary,
            EvidenceSummary);
}
