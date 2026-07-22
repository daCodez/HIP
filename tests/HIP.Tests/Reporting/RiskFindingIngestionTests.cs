using HIP.Application.Reporting;
using HIP.Application.Review;
using HIP.Application.SelfHealing;
using HIP.Domain.Reporting;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Domain.SelfHealing;

namespace HIP.Tests.Reporting;

/// <summary>
/// Verifies privacy-safe risk finding ingestion and related client payload contracts.
/// </summary>
public sealed class RiskFindingIngestionTests
{
    [Test]
    public async Task Valid_privacy_safe_report_is_accepted()
    {
        var service = Service();

        var response = await service.IngestAsync(Report(), CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(response.ReportId, Is.Not.Empty);
    }

    [Test]
    public async Task Report_with_private_content_flag_is_rejected()
    {
        var service = Service();
        var report = Report() with
        {
            PrivacySafeEvidence = Evidence() with { ContainsPrivateContent = true }
        };

        var response = await service.IngestAsync(report, CancellationToken.None);

        Assert.That(response.Accepted, Is.False);
        Assert.That(response.Message, Does.Contain("private content"));
    }

    [Test]
    public async Task Url_hash_is_generated_when_needed()
    {
        var service = Service();
        var report = Report() with { UrlHash = null, OriginalUrl = "https://Example.com/suspicious" };

        var response = await service.IngestAsync(report, CancellationToken.None);
        var stored = await service.ListReportsAsync(CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(stored.Single().UrlHash, Does.StartWith("sha256:"));
    }

    [Test]
    public async Task Domain_is_normalized()
    {
        var service = Service();

        var response = await service.IngestAsync(Report() with { Domain = "WWW.Example.COM." }, CancellationToken.None);

        Assert.That(response.NormalizedDomain, Is.EqualTo("example.com"));
    }

    [TestCase(ReporterTrustLevel.High)]
    [TestCase(ReporterTrustLevel.Trusted)]
    public async Task Trusted_high_risk_report_creates_review_item(ReporterTrustLevel reporterTrustLevel)
    {
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
        var review = new ReviewQueueService(new ReviewItemValidator(), new InMemoryReviewQueueRepository(), audit);
        var service = Service(review);

        var response = await service.IngestAsync(
            Report(RiskStatus.HighRisk) with { ReporterTrustLevel = reporterTrustLevel },
            CancellationToken.None);

        Assert.That(response.ReviewCreated, Is.True);
        Assert.That(review.List(), Has.Count.EqualTo(1));
    }

    [TestCase(ReporterTrustLevel.Unknown)]
    [TestCase(ReporterTrustLevel.Low)]
    [TestCase(ReporterTrustLevel.Medium)]
    public async Task Untrusted_high_risk_report_does_not_create_review_item(ReporterTrustLevel reporterTrustLevel)
    {
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
        var review = new ReviewQueueService(new ReviewItemValidator(), new InMemoryReviewQueueRepository(), audit);
        var service = Service(review);

        var response = await service.IngestAsync(
            Report(RiskStatus.Critical) with { ReporterTrustLevel = reporterTrustLevel },
            CancellationToken.None);

        Assert.That(response.ReviewCreated, Is.False);
        Assert.That(review.List(), Is.Empty);
    }

    [Test]
    public async Task Low_risk_report_does_not_always_create_review_item()
    {
        var audit = new AuditLogService(new InMemoryAuditLogRepository());
        var review = new ReviewQueueService(new ReviewItemValidator(), new InMemoryReviewQueueRepository(), audit);
        var service = Service(review);

        var response = await service.IngestAsync(Report(RiskStatus.Caution), CancellationToken.None);

        Assert.That(response.ReviewCreated, Is.False);
        Assert.That(review.List(), Is.Empty);
    }

    [TestCase(ReporterTrustLevel.High)]
    [TestCase(ReporterTrustLevel.Trusted)]
    public async Task Trusted_report_can_feed_self_healing_path(ReporterTrustLevel reporterTrustLevel)
    {
        var service = Service();

        await service.IngestAsync(
            Report(RiskStatus.HighRisk) with
            {
                Domain = "cluster.example",
                Reason = "Shortened URL abuse detected",
                ReporterTrustLevel = reporterTrustLevel
            },
            CancellationToken.None);
        await service.IngestAsync(
            Report(RiskStatus.HighRisk) with
            {
                Domain = "cluster.example",
                Reason = "Shortened URL abuse detected",
                UrlHash = "sha256:two",
                ReporterTrustLevel = reporterTrustLevel
            },
            CancellationToken.None);

        var clusters = await service.DetectPatternsAsync(CancellationToken.None);

        Assert.That(clusters, Has.Count.EqualTo(1));
        Assert.That(clusters.Single().PatternType, Is.EqualTo(FindingType.ShortenedUrlAbuse));
    }

    [TestCase(ReporterTrustLevel.Unknown)]
    [TestCase(ReporterTrustLevel.Low)]
    [TestCase(ReporterTrustLevel.Medium)]
    public async Task Untrusted_reports_do_not_feed_self_healing_path(ReporterTrustLevel reporterTrustLevel)
    {
        var service = Service();

        await service.IngestAsync(
            Report(RiskStatus.HighRisk) with
            {
                Domain = "untrusted-cluster.example",
                Reason = "Shortened URL abuse detected",
                ReporterTrustLevel = reporterTrustLevel
            },
            CancellationToken.None);
        await service.IngestAsync(
            Report(RiskStatus.HighRisk) with
            {
                Domain = "untrusted-cluster.example",
                Reason = "Shortened URL abuse detected",
                UrlHash = "sha256:two",
                ReporterTrustLevel = reporterTrustLevel
            },
            CancellationToken.None);

        var clusters = await service.DetectPatternsAsync(CancellationToken.None);

        Assert.That(clusters, Is.Empty);
    }

    [Test]
    public async Task Api_response_does_not_expose_private_data()
    {
        var service = Service();

        var response = await service.IngestAsync(Report() with { OriginalUrl = "https://example.com/private-path" }, CancellationToken.None);

        Assert.That(response.Accepted, Is.True);
        Assert.That(typeof(RiskFindingIngestionResponse).GetProperties().Select(property => property.Name), Does.Not.Contain("OriginalUrl"));
        Assert.That(typeof(RiskFindingIngestionResponse).GetProperties().Select(property => property.Name), Does.Not.Contain("PrivacySafeEvidence"));
    }

    [Test]
    public void Browser_plugin_report_payload_avoids_page_body_text()
    {
        var contentScript = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "clients", "browser-extension", "src", "content.js"));

        Assert.That(contentScript, Does.Contain("HIP_REPORT_RISK_FINDING"));
        Assert.That(contentScript, Does.Not.Contain("document.body"));
        Assert.That(contentScript, Does.Not.Contain("innerText"));
        Assert.That(contentScript, Does.Not.Contain("form contents"));
    }

    private static RiskFindingIngestionService Service(IReviewQueueService? reviewQueueService = null) =>
        new(
            new RiskFindingReportValidator(),
            new InMemoryRiskFindingReportRepository(),
            reviewQueueService ?? new ReviewQueueService(new ReviewItemValidator(), new InMemoryReviewQueueRepository(), new AuditLogService(new InMemoryAuditLogRepository())),
            new PatternDetectionService(),
            new Sha256PrivacyHashingService());

    private static RiskFindingReport Report(RiskStatus riskStatus = RiskStatus.HighRisk) =>
        new(
            "",
            SourceClient.BrowserPlugin,
            ReportPlatform.Web,
            TargetType.Url,
            "Example.com",
            "sha256:one",
            null,
            null,
            riskStatus,
            "Suspicious redirect pattern.",
            DateTimeOffset.UtcNow,
            ReporterTrustLevel.Medium,
            Evidence(),
            "signature-placeholder");

    private static PrivacySafeEvidence Evidence() =>
        new(
            "browser-link-risk",
            "Browser plugin reported a risky link domain without page body text.",
            new Dictionary<string, string>
            {
                ["sourceDomain"] = "source.example",
                ["targetDomain"] = "example.com"
            });

    /// <summary>
    /// Finds the repository root from any test output folder so privacy contract tests can read client scripts.
    /// </summary>
    /// <returns>The absolute repository root.</returns>
    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "HIP.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate HIP.slnx from the test output directory.");
    }
}
