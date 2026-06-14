using System.Text.Json;
using FluentValidation;
using HIP.Application.Browser;
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

        Assert.That(items.Single().ReviewReason, Is.EqualTo("RepeatedLooksSuspiciousFeedback"));
    }

    /// <summary>
    /// Weighted safe feedback can create a false-positive review item without directly changing scoring.
    /// </summary>
    [Test]
    public async Task Possible_false_positive_feedback_creates_review_signal()
    {
        var service = CreateService();
        var summary = new WeightedFeedbackSummary(
            "false-positive.example",
            LooksSafeWeight: 18,
            LooksSuspiciousWeight: 2,
            ReportIssueWeight: 0,
            RecentFeedbackCount: 9,
            RepeatedReporterCount: 1,
            SuspiciousFeedbackPattern: false,
            ConflictingFeedbackSpike: false,
            ConfidenceImpact: 10,
            RecommendedReview: false,
            ["Users say this warning may be a false positive."]);

        var items = await service.CreateSignalsFromFeedbackAsync(summary, CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("PossibleFalsePositive"));
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
    /// Dangerous admin-created rule overrides are forced into review before enforcement.
    /// </summary>
    [Test]
    public async Task Dangerous_admin_rule_override_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromAdminRuleAsync(AdminRule(SiteSafetyScanStatus.Dangerous), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(items.Single().ReviewReason, Is.EqualTo("DangerousAdminRuleOverride"));
            Assert.That(items.Single().Severity, Is.EqualTo(AdminReviewSeverity.Critical));
            Assert.That(items.Single().RelatedRuleId, Is.EqualTo("admin-rule-dangerous"));
        });
    }

    /// <summary>
    /// Repeated suspicious browser scan summaries create one review item per domain.
    /// </summary>
    [Test]
    public async Task Repeated_suspicious_scan_history_creates_review_signal()
    {
        var service = CreateService();
        var scans = new[]
        {
            BrowserScan("scan-1", SuspiciousLinksFound: 1),
            BrowserScan("scan-2", RiskyLinksFound: 1),
            BrowserScan("scan-3", DangerousLinksFound: 1)
        };

        var items = await service.CreateSignalsFromScanHistoryAsync(scans, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(items.Single().ReviewReason, Is.EqualTo("RepeatedSuspiciousScanHistory"));
            Assert.That(items.Single().UrlHash, Is.EqualTo("sha256:scan-3"));
            Assert.That(items.Single().EvidenceSummary, Does.Not.Contain("https://"));
        });
    }

    /// <summary>
    /// Sudden score movement creates review evidence because reputation changes should be explainable.
    /// </summary>
    [Test]
    public async Task Sudden_reputation_change_creates_review_signal()
    {
        var service = CreateService();

        var items = await service.CreateSignalsFromReputationChangeAsync(
            "reputation.example",
            "domain:reputation.example",
            previousScore: 76,
            currentScore: 28,
            reasonSummary: "Multiple confirmed privacy-safe abuse reports.",
            CancellationToken.None);

        Assert.That(items.Single().ReviewReason, Is.EqualTo("SuddenReputationChange"));
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
    /// Scan-history review items never copy raw stored page URLs or private metadata into summaries.
    /// </summary>
    [Test]
    public async Task Scan_history_review_signal_does_not_store_private_data()
    {
        var service = CreateService();
        var scans = new[]
        {
            BrowserScan("scan-private-1", SuspiciousLinksFound: 1, StoredPageUrl: "https://example.com/login?token=secret"),
            BrowserScan("scan-private-2", SuspiciousLinksFound: 1, StoredPageUrl: "https://example.com/login?password=secret"),
            BrowserScan("scan-private-3", SuspiciousLinksFound: 1, StoredPageUrl: "https://example.com/login?cookie=secret")
        };

        var item = (await service.CreateSignalsFromScanHistoryAsync(scans, CancellationToken.None)).Single();

        Assert.Multiple(() =>
        {
            Assert.That(item.Summary, Does.Not.Contain("token="));
            Assert.That(item.EvidenceSummary, Does.Not.Contain("password"));
            Assert.That(item.EvidenceSummary, Does.Not.Contain("cookie"));
            Assert.That(item.EvidenceSummary, Does.Not.Contain("https://"));
        });
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
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
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
            auditLogService ?? new AuditLogService(new InMemoryAuditLogRepository()));

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
    /// Builds an admin-managed rule that requests a status override through the safe structured rule format.
    /// </summary>
    private static AdminSiteSafetyRule AdminRule(SiteSafetyScanStatus statusOverride) =>
        new(
            "admin-rule-dangerous",
            "Dangerous override request",
            "Requests a dangerous override for test evidence.",
            AdminSiteSafetyRuleTargetType.PageContent,
            [new AdminSiteSafetyRuleCondition("KnownAbuseReports", AdminSiteSafetyRuleOperator.GreaterThan, JsonSerializer.SerializeToElement(0))],
            new AdminSiteSafetyRuleEffects(SetStatusOverride: statusOverride, SendToAdminReview: true),
            SiteSafetyRuleSeverity.Critical,
            SiteSafetyEvidenceQuality.Strong,
            AdminSiteSafetyRuleStatus.PendingApproval,
            AdminSiteSafetyRuleMode.Simulation,
            "admin-test",
            DateTimeOffset.UtcNow,
            null,
            null,
            Version: 1,
            PreviousVersionId: null,
            IsRollbackAvailable: false);

    /// <summary>
    /// Builds a privacy-safe browser scan summary with a URL hash and no page content.
    /// </summary>
    private static BrowserScanResultRecord BrowserScan(
        string scanId,
        int RiskyLinksFound = 0,
        int SuspiciousLinksFound = 0,
        int DangerousLinksFound = 0,
        string? StoredPageUrl = null) =>
        new(
            scanId,
            "history.example",
            $"sha256:{scanId}",
            StoredPageUrl,
            "BrowserPlugin",
            Score: DangerousLinksFound > 0 ? 18 : 38,
            RiskLevel: DangerousLinksFound > 0 ? "Dangerous" : "Suspicious",
            Status: DangerousLinksFound > 0 ? "Dangerous" : "Suspicious",
            ["Privacy-safe browser scan summary."],
            LinksScanned: 12,
            RiskyLinksFound,
            SuspiciousLinksFound,
            DangerousLinksFound,
            DateTimeOffset.UtcNow.AddMinutes(scanId.EndsWith('3') ? 3 : 0),
            RecommendedAction: "RouteToSafetyPage",
            new Dictionary<string, string>
            {
                ["source"] = "BrowserPlugin"
            });

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
