using HIP.Application.Review;
using HIP.Application.SiteSafety;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.SiteSafety;

/// <summary>
/// Tests admin review evidence as a transparent Site Safety provider.
/// </summary>
[TestFixture]
public sealed class AdminReviewEvidenceProviderTests
{
    /// <summary>
    /// Resolved admin decisions are exposed as normalized provider evidence.
    /// </summary>
    [Test]
    public async Task Resolved_admin_decision_returns_provider_evidence()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        var review = await CreateResolvedReviewAsync(repository, AdminReviewDecision.ConfirmSuspicious);
        var provider = new AdminReviewEvidenceProvider(repository);
        var context = Context("https://review.example/path");

        var evidence = await provider.CollectEvidenceAsync(context, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(review.Status, Is.EqualTo(AdminReviewStatus.Resolved));
            Assert.That(evidence.ProviderType, Is.EqualTo(SiteSafetyEvidenceProviderType.AdminReview));
            Assert.That(evidence.EvidenceItems.Single().Category, Is.EqualTo("AdminConfirmSuspicious"));
        });
    }

    /// <summary>
    /// Admin-confirmed safe evidence can add small support but cannot make a limited-data site trusted.
    /// </summary>
    [Test]
    public async Task Admin_safe_decision_does_not_make_unknown_site_trusted()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        await CreateResolvedReviewAsync(repository, AdminReviewDecision.ConfirmSafe);
        var scanner = Scanner(repository);

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://review.example/path"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
            Assert.That(result.MatchedRules!, Has.Some.Property(nameof(SiteSafetyRuleResult.RuleId)).EqualTo("admin-review-safe"));
        });
    }

    /// <summary>
    /// Admin-confirmed dangerous evidence can force a dangerous Site Safety result through explicit rules.
    /// </summary>
    [Test]
    public async Task Admin_dangerous_decision_forces_dangerous_status()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        await CreateResolvedReviewAsync(repository, AdminReviewDecision.ConfirmDangerous);
        var scanner = Scanner(repository);

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://review.example/path"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.ReputationRiskScore, Is.EqualTo(90));
            Assert.That(result.ProviderEvidence.SelectMany(evidence => evidence.EvidenceItems), Has.Some.Property(nameof(SiteSafetyEvidenceItem.Category)).EqualTo("AdminConfirmDangerous"));
        });
    }

    /// <summary>
    /// Admin decisions that need more data lower confidence without directly changing risk status.
    /// </summary>
    [Test]
    public async Task Admin_needs_more_data_lowers_confidence()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        await CreateResolvedReviewAsync(repository, AdminReviewDecision.NeedsMoreData);
        var scanner = Scanner(repository);

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://review.example/path"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.ConfidenceLevel, Is.EqualTo("Medium"));
            Assert.That(result.MatchedRules!, Has.Some.Property(nameof(SiteSafetyRuleResult.RuleId)).EqualTo("admin-review-needs-more-data"));
        });
    }

    /// <summary>
    /// Dismissed or no-action review records do not influence scoring.
    /// </summary>
    [Test]
    public async Task Dismissed_review_decision_is_ignored()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        var service = Service(repository);
        var item = await service.CreateSignalAsync(Signal("review.example", null), CancellationToken.None);
        await service.DismissAsync(item.ReviewId, "admin", "No action needed.", CancellationToken.None);
        var scanner = Scanner(repository);

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://review.example/path"), CancellationToken.None);

        Assert.That(AdminReviewItems(result), Is.Empty);
    }

    /// <summary>
    /// URL-hash-specific admin decisions do not affect unrelated pages on the same domain.
    /// </summary>
    [Test]
    public async Task Url_hash_specific_decision_does_not_affect_other_page()
    {
        var repository = new InMemoryAdminReviewQueueRepository();
        var firstPageHash = SiteSafetyEvidenceHashing.HashUrl("https://review.example/first");
        await CreateResolvedReviewAsync(repository, AdminReviewDecision.ConfirmHighRisk, firstPageHash);
        var scanner = Scanner(repository);

        var result = await scanner.ScanAsync(new SiteSafetyScanRequest("https://review.example/second"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(AdminReviewItems(result), Is.Empty);
            Assert.That(result.Status, Is.EqualTo(SiteSafetyScanStatus.LimitedData));
        });
    }

    /// <summary>
    /// Enumerates admin-review evidence items from a scan result.
    /// </summary>
    private static IReadOnlyCollection<SiteSafetyEvidenceItem> AdminReviewItems(SiteSafetyScanResult result) =>
        result.ProviderEvidence
            .Where(evidence => evidence.ProviderType == SiteSafetyEvidenceProviderType.AdminReview)
            .SelectMany(evidence => evidence.EvidenceItems)
            .ToArray();

    /// <summary>
    /// Creates a resolved review item through the service so validation, redaction, and audit behavior match production.
    /// </summary>
    private static async Task<AdminReviewQueueItem> CreateResolvedReviewAsync(
        IAdminReviewQueueRepository repository,
        AdminReviewDecision decision,
        string? urlHash = null)
    {
        var service = Service(repository);
        var item = await service.CreateSignalAsync(Signal("review.example", urlHash), CancellationToken.None);
        return await service.RecordDecisionAsync(item.ReviewId, new HIP.Application.Review.AdminReviewDecisionRequest(
            decision,
            "Privacy-safe admin review evidence.",
            "admin-test"), CancellationToken.None);
    }

    /// <summary>
    /// Creates the admin review queue service used by provider tests.
    /// </summary>
    private static AdminReviewQueueService Service(IAdminReviewQueueRepository repository) =>
        new(
            repository,
            new AdminReviewQueueItemValidator(),
            new AuditLogService());

    /// <summary>
    /// Creates a scanner with the browser-observed and admin-review providers active.
    /// </summary>
    private static SiteSafetyScanner Scanner(IAdminReviewQueueRepository repository) =>
        new(
            new SiteSafetyScanValidator(),
            NullLogger<SiteSafetyScanner>.Instance,
            [
                new BrowserObservedSignalProvider(),
                new AdminReviewEvidenceProvider(repository)
            ],
            new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero });

    /// <summary>
    /// Builds a privacy-safe review signal.
    /// </summary>
    private static AdminReviewSignal Signal(string domain, string? urlHash) =>
        new(
            domain,
            urlHash,
            AdminReviewTargetType.Url,
            "AdminReviewEvidenceProviderTest",
            AdminReviewSeverity.Medium,
            AdminReviewSource.SiteSafetyScan,
            "scan-test",
            null,
            null,
            56,
            "LimitedData",
            "Medium",
            "Privacy-safe review signal.",
            "Domain and URL-hash evidence only.");

    /// <summary>
    /// Builds provider context without raw page content.
    /// </summary>
    private static SiteSafetyEvidenceContext Context(string url)
    {
        var uri = new Uri(url);
        return new SiteSafetyEvidenceContext(
            uri,
            uri.Host,
            SiteSafetyEvidenceHashing.HashUrl(url),
            new SiteSafetyObservedSignals(),
            DateTimeOffset.UtcNow);
    }
}
