using System.Text.Json;
using HIP.Application.Reputation;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;
using Microsoft.Extensions.Logging.Abstractions;

namespace HIP.Tests.Reputation;

/// <summary>
/// Tests weighted HIP trust feedback as a weak evidence source, not a voting system.
/// </summary>
[TestFixture]
public sealed class WeightedFeedbackAggregationTests
{
    /// <summary>
    /// Anonymous safe feedback has the weakest positive weight.
    /// </summary>
    [Test]
    public async Task Anonymous_looks_safe_has_weak_positive_impact()
    {
        var service = Service();

        var summary = await service.SubmitAsync(Submission("safe.example", HipFeedbackType.LooksSafe, ReporterTrustLevel.Anonymous), CancellationToken.None);

        Assert.That(summary.LooksSafeWeight, Is.EqualTo(1));
    }

    /// <summary>
    /// Anonymous suspicious feedback has the weakest negative weight.
    /// </summary>
    [Test]
    public async Task Anonymous_looks_suspicious_has_weak_negative_impact()
    {
        var service = Service();

        var summary = await service.SubmitAsync(Submission("suspicious.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Anonymous), CancellationToken.None);

        Assert.That(summary.LooksSuspiciousWeight, Is.EqualTo(1));
    }

    /// <summary>
    /// Reporter trust levels increase feedback weight conservatively.
    /// </summary>
    [Test]
    public async Task Reporter_trust_levels_have_ordered_weights()
    {
        var service = Service();
        var anonymous = await service.SubmitAsync(Submission("anon.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Anonymous), CancellationToken.None);
        var verified = await service.SubmitAsync(Submission("verified.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Verified), CancellationToken.None);
        var trusted = await service.SubmitAsync(Submission("trusted.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Trusted), CancellationToken.None);
        var admin = await service.SubmitAsync(Submission("admin.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Admin), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(verified.LooksSuspiciousWeight, Is.GreaterThan(anonymous.LooksSuspiciousWeight));
            Assert.That(trusted.LooksSuspiciousWeight, Is.GreaterThan(verified.LooksSuspiciousWeight));
            Assert.That(admin.LooksSuspiciousWeight, Is.GreaterThan(trusted.LooksSuspiciousWeight));
        });
    }

    /// <summary>
    /// One anonymous safe feedback signal cannot make an unknown domain trusted.
    /// </summary>
    [Test]
    public async Task One_anonymous_looks_safe_cannot_make_unknown_site_trusted()
    {
        var service = Service();
        await service.SubmitAsync(Submission("unknown-safe.example", HipFeedbackType.LooksSafe, ReporterTrustLevel.Anonymous), CancellationToken.None);

        var result = await Scanner(service).ScanAsync(new SiteSafetyScanRequest("https://unknown-safe.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Clean));
            Assert.That(result.FinalHipScore, Is.LessThan(70));
            Assert.That(result.MatchedRules ?? [], Has.Some.Property(nameof(SiteSafetyRuleResult.RuleId)).EqualTo("feedback-looks-safe"));
        });
    }

    /// <summary>
    /// One anonymous suspicious feedback signal cannot make a site dangerous.
    /// </summary>
    [Test]
    public async Task One_anonymous_looks_suspicious_cannot_make_site_dangerous()
    {
        var service = Service();
        await service.SubmitAsync(Submission("single-risk.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Anonymous), CancellationToken.None);

        var result = await Scanner(service).ScanAsync(new SiteSafetyScanRequest("https://single-risk.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.ReputationRiskScore, Is.GreaterThan(0));
            Assert.That(result.MalwareRiskScore, Is.EqualTo(0));
            Assert.That(result.PhishingRiskScore, Is.EqualTo(0));
        });
    }

    /// <summary>
    /// Many low-trust reports create a review signal instead of instantly marking a site dangerous.
    /// </summary>
    [Test]
    public async Task Many_low_trust_reports_trigger_review_signal_instead_of_dangerous()
    {
        var service = Service();
        for (var index = 0; index < 8; index++)
        {
            await service.SubmitAsync(Submission("pile-on.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Anonymous, reporterHash: "same-browser"), CancellationToken.None);
        }

        var result = await Scanner(service).ScanAsync(new SiteSafetyScanRequest("https://pile-on.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Status, Is.Not.EqualTo(SiteSafetyScanStatus.Dangerous));
            Assert.That(result.MatchedRules ?? [], Has.Some.Property(nameof(SiteSafetyRuleResult.RuleId)).EqualTo("feedback-review-signal"));
            Assert.That(result.Warnings, Has.Some.Contains("Feedback patterns recommend admin review"));
        });
    }

    /// <summary>
    /// Conflicting feedback lowers confidence and avoids claiming a definitive result.
    /// </summary>
    [Test]
    public async Task Conflicting_feedback_lowers_confidence()
    {
        var service = Service();
        await service.SubmitAsync(Submission("conflict.example", HipFeedbackType.LooksSafe, ReporterTrustLevel.Trusted), CancellationToken.None);
        await service.SubmitAsync(Submission("conflict.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Trusted), CancellationToken.None);

        var result = await Scanner(service).ScanAsync(new SiteSafetyScanRequest("https://conflict.example"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.ConfidenceLevel, Is.Not.EqualTo("High"));
            Assert.That(result.MatchedRules ?? [], Has.Some.Property(nameof(SiteSafetyRuleResult.RuleId)).EqualTo("feedback-conflict"));
            Assert.That(result.Reasons, Has.Some.Contains("Recent feedback is conflicting"));
        });
    }

    /// <summary>
    /// Feedback aggregation returns safe totals without storing private content fields.
    /// </summary>
    [Test]
    public async Task Feedback_aggregation_returns_safe_totals_and_payload_shape()
    {
        var service = Service();
        await service.SubmitAsync(Submission("totals.example", HipFeedbackType.LooksSafe, ReporterTrustLevel.Verified, pageHash: "sha256:page"), CancellationToken.None);
        await service.SubmitAsync(Submission("totals.example", HipFeedbackType.ReportIssue, ReporterTrustLevel.Admin, pageHash: "sha256:page"), CancellationToken.None);

        var summary = await service.GetSummaryAsync("totals.example", CancellationToken.None);
        var propertyNames = typeof(WeightedFeedbackSubmission).GetProperties().Select(property => property.Name).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(summary.LooksSafeWeight, Is.EqualTo(3));
            Assert.That(summary.ReportIssueWeight, Is.EqualTo(10));
            Assert.That(summary.RecommendedReview, Is.True);
            Assert.That(propertyNames, Does.Not.Contain("PageText"));
            Assert.That(propertyNames, Does.Not.Contain("FormValues"));
            Assert.That(propertyNames, Does.Not.Contain("Cookies"));
            Assert.That(propertyNames, Does.Not.Contain("RawUrl"));
        });
    }

    /// <summary>
    /// Private-looking content is rejected before feedback is stored.
    /// </summary>
    [Test]
    public void Feedback_rejects_private_content_markers()
    {
        var service = Service();
        var submission = Submission("private.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Anonymous, pageHash: "typed-form-value=password");

        var exception = Assert.ThrowsAsync<ArgumentException>(() => service.SubmitAsync(submission, CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain("does not accept"));
    }

    /// <summary>
    /// Feedback explanations avoid voting language.
    /// </summary>
    [Test]
    public async Task Feedback_explanations_avoid_voting_language()
    {
        var service = Service();
        var summary = await service.SubmitAsync(Submission("language.example", HipFeedbackType.LooksSuspicious, ReporterTrustLevel.Verified), CancellationToken.None);
        var serialized = JsonSerializer.Serialize(summary.Explanations);

        Assert.Multiple(() =>
        {
            Assert.That(serialized, Does.Not.Contain("voted"));
            Assert.That(serialized, Does.Not.Contain("vote"));
            Assert.That(serialized, Does.Contain("reported"));
        });
    }

    /// <summary>
    /// Creates a feedback aggregation service with an in-memory repository.
    /// </summary>
    private static WeightedFeedbackAggregationService Service() =>
        new(new InMemoryWeightedFeedbackRepository());

    /// <summary>
    /// Creates a scanner with only browser-observed and weighted-feedback evidence providers.
    /// </summary>
    private static SiteSafetyScanner Scanner(IWeightedFeedbackAggregationService service) =>
        new(
            new SiteSafetyScanValidator(),
            NullLogger<SiteSafetyScanner>.Instance,
            [new BrowserObservedSignalProvider(), new WeightedFeedbackSiteSafetyEvidenceProvider(service)],
            new SiteSafetyRuleOptions { ScanCacheDuration = TimeSpan.Zero });

    /// <summary>
    /// Creates a privacy-safe feedback submission for tests.
    /// </summary>
    private static WeightedFeedbackSubmission Submission(
        string domain,
        HipFeedbackType feedbackType,
        ReporterTrustLevel trustLevel,
        string? reporterHash = null,
        string? pageHash = "sha256:page") =>
        new(
            domain,
            feedbackType,
            HipFeedbackSource.BrowserPluginBanner,
            trustLevel,
            DateTimeOffset.UtcNow,
            pageHash,
            reporterHash,
            "0.1.0-dev",
            HipFeedbackReasonCode.Other);
}
