using HIP.Application.Reputation;
using HIP.Tests.Support;
using HIP.Domain.Reputation;
using HIP.Domain.Risk;
using Microsoft.Extensions.Logging;

namespace HIP.Tests.Reputation;

public sealed class ReputationServiceTests
{
    [Test]
    public async Task New_reputation_profile_starts_with_reasonable_default_score()
    {
        var service = Service();

        var profile = await service.GetProfileAsync(ReputationSubjectType.Domain, "example.com", CancellationToken.None);

        Assert.That(profile.CurrentScore, Is.EqualTo(ReputationService.DefaultScore));
        Assert.That(profile.Status, Is.EqualTo(RiskStatus.ProbablySafe));
    }

    [Test]
    public async Task Anonymous_feedback_has_lower_impact_than_trusted_feedback()
    {
        var anonymous = Service();
        var trusted = Service();

        var anonymousProfile = await anonymous.SubmitFeedbackAsync(Feedback("anon.example", ReporterTrustLevel.Anonymous), CancellationToken.None);
        var trustedProfile = await trusted.SubmitFeedbackAsync(Feedback("trusted.example", ReporterTrustLevel.Trusted), CancellationToken.None);

        Assert.That(anonymousProfile.CurrentScore, Is.GreaterThan(trustedProfile.CurrentScore));
    }

    [Test]
    public async Task Known_false_reporter_has_very_low_impact()
    {
        var service = Service();

        var profile = await service.SubmitFeedbackAsync(Feedback("false-reporter.example", ReporterTrustLevel.KnownFalseReporter), CancellationToken.None);

        Assert.That(profile.CurrentScore, Is.GreaterThanOrEqualTo(73));
    }

    [Test]
    public void Unknown_reporter_trust_level_falls_back_to_anonymous_weight()
    {
        var service = Service();
        var unknownTrustLevel = (ReporterTrustLevel)999;
        var unknownReporterScore = service.CalculateScore([
            Event(ReputationEventType.SuspiciousReport, ReputationEventSeverity.High, -20, unknownTrustLevel)
        ], DateTimeOffset.UtcNow);
        var anonymousReporterScore = service.CalculateScore([
            Event(ReputationEventType.SuspiciousReport, ReputationEventSeverity.High, -20, ReporterTrustLevel.Anonymous)
        ], DateTimeOffset.UtcNow);

        Assert.That(unknownReporterScore, Is.EqualTo(anonymousReporterScore));
    }

    [Test]
    public void Accidental_issue_decays()
    {
        var service = Service();
        var oldEvent = Event(
            ReputationEventType.AccidentalIssue,
            ReputationEventSeverity.Low,
            -10,
            ReporterTrustLevel.Admin,
            DateTimeOffset.UtcNow.AddDays(-120),
            isConfirmed: false,
            isAccidental: true,
            expiresAtUtc: DateTimeOffset.UtcNow.AddDays(-30));

        var score = service.CalculateScore([oldEvent], DateTimeOffset.UtcNow);

        Assert.That(score, Is.EqualTo(ReputationService.DefaultScore));
    }

    [Test]
    public void Confirmed_malicious_event_does_not_fully_decay()
    {
        var service = Service();
        var oldEvent = Event(
            ReputationEventType.ConfirmedMaliciousBehavior,
            ReputationEventSeverity.Critical,
            -60,
            ReporterTrustLevel.Admin,
            DateTimeOffset.UtcNow.AddDays(-900),
            isConfirmed: true,
            isAccidental: false,
            expiresAtUtc: null);

        var score = service.CalculateScore([oldEvent], DateTimeOffset.UtcNow);

        Assert.That(score, Is.LessThanOrEqualTo(45));
    }

    [Test]
    public void Repeated_abuse_causes_stronger_penalty()
    {
        var service = Service();
        var oneEventScore = service.CalculateScore([
            Event(ReputationEventType.RepeatedAbuse, ReputationEventSeverity.High, -20, ReporterTrustLevel.Admin)
        ], DateTimeOffset.UtcNow);
        var repeatedScore = service.CalculateScore([
            Event(ReputationEventType.RepeatedAbuse, ReputationEventSeverity.High, -20, ReporterTrustLevel.Admin),
            Event(ReputationEventType.RepeatedAbuse, ReputationEventSeverity.High, -20, ReporterTrustLevel.Admin)
        ], DateTimeOffset.UtcNow);

        Assert.That(repeatedScore, Is.LessThan(oneEventScore - 20));
    }

    [Test]
    public void Score_never_goes_below_zero_or_above_one_hundred()
    {
        var service = Service();

        var low = service.CalculateScore(Enumerable.Range(0, 10)
            .Select(_ => Event(ReputationEventType.ConfirmedMaliciousBehavior, ReputationEventSeverity.Critical, -80, ReporterTrustLevel.Admin))
            .ToArray(), DateTimeOffset.UtcNow);
        var high = service.CalculateScore(Enumerable.Range(0, 10)
            .Select(_ => Event(ReputationEventType.PositiveReport, ReputationEventSeverity.High, 50, ReporterTrustLevel.Admin))
            .ToArray(), DateTimeOffset.UtcNow);

        Assert.That(low, Is.EqualTo(0));
        Assert.That(high, Is.EqualTo(100));
    }

    [TestCase(20, RiskStatus.Dangerous)]
    [TestCase(40, RiskStatus.HighRisk)]
    [TestCase(60, RiskStatus.Caution)]
    [TestCase(80, RiskStatus.ProbablySafe)]
    [TestCase(81, RiskStatus.Trusted)]
    public void Score_maps_to_correct_status(int score, RiskStatus expected)
    {
        var service = Service();

        Assert.That(service.CalculateStatus(score), Is.EqualTo(expected));
    }

    [Test]
    public async Task Explanation_is_returned()
    {
        var service = Service();

        var profile = await service.SubmitFeedbackAsync(Feedback("explain.example", ReporterTrustLevel.Trusted), CancellationToken.None);

        Assert.That(profile.Explanations, Is.Not.Empty);
        Assert.That(profile.Explanations.Any(explanation => explanation.Contains("privacy-safe", StringComparison.OrdinalIgnoreCase)), Is.True);
    }

    [Test]
    public async Task Public_feedback_does_not_require_private_chat_logs()
    {
        var service = Service();
        var feedback = new ReputationFeedbackRequest(
            ReputationSubjectType.Url,
            "https://example.com/path",
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.Medium,
            ReporterTrustLevel.Verified,
            "Suspicious redirect pattern.",
            "browser-extension",
            "sha256:url");

        var profile = await service.SubmitFeedbackAsync(feedback, CancellationToken.None);

        Assert.That(profile.EventCount, Is.EqualTo(1));
        Assert.That(typeof(ReputationFeedbackRequest).GetProperties().Select(property => property.Name), Does.Not.Contain("PrivateChatLog"));
    }

    [Test]
    public async Task SubmitFeedbackAsync_logs_reputation_update_without_private_reason()
    {
        var logger = new CapturingLogger<ReputationService>();
        var service = Service(logger);
        var feedback = new ReputationFeedbackRequest(
            ReputationSubjectType.Domain,
            "log-safe.example",
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.High,
            ReporterTrustLevel.Trusted,
            "Suspicious redirect report with token=private-marker.",
            "browser-extension",
            "sha256:sample");

        await service.SubmitFeedbackAsync(feedback, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Information &&
                entry.Message.Contains("Appended reputation event", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Information &&
                entry.Message.Contains("Recalculated reputation profile", StringComparison.OrdinalIgnoreCase)), Is.True);
            Assert.That(logger.Messages.Any(message => message.Contains("token=private-marker", StringComparison.OrdinalIgnoreCase)), Is.False);
        });
    }

    [Test]
    public void SubmitFeedbackAsync_logs_missing_reason_rejection()
    {
        var logger = new CapturingLogger<ReputationService>();
        var service = Service(logger);
        var feedback = new ReputationFeedbackRequest(
            ReputationSubjectType.Domain,
            "missing-reason.example",
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.Medium,
            ReporterTrustLevel.Anonymous,
            "",
            "browser-extension",
            "sha256:sample");

        var exception = Assert.ThrowsAsync<ArgumentException>(() => service.SubmitFeedbackAsync(feedback, CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Contain("Feedback reason is required"));
            Assert.That(logger.Entries.Any(entry =>
                entry.LogLevel == LogLevel.Warning &&
                entry.Message.Contains("Rejected reputation feedback", StringComparison.OrdinalIgnoreCase)), Is.True);
        });
    }

    private static ReputationService Service(CapturingLogger<ReputationService>? logger = null) =>
        new(
            new InMemoryReputationEventRepository(),
            new InMemoryReputationProfileRepository(),
            new DefaultReputationScoringPolicy(),
            logger);

    private static ReputationFeedbackRequest Feedback(string targetId, ReporterTrustLevel reporterTrustLevel) =>
        new(
            ReputationSubjectType.Domain,
            targetId,
            ReputationEventType.SuspiciousReport,
            ReputationEventSeverity.High,
            reporterTrustLevel,
            "Suspicious redirect report.",
            "browser-extension",
            "sha256:sample");

    private static ReputationEvent Event(
        ReputationEventType eventType,
        ReputationEventSeverity severity,
        int scoreImpact,
        ReporterTrustLevel reporterTrustLevel,
        DateTimeOffset? createdAtUtc = null,
        bool isConfirmed = true,
        bool isAccidental = false,
        DateTimeOffset? expiresAtUtc = null) =>
        new(
            $"event-{Guid.NewGuid():N}",
            ReputationSubjectType.Domain,
            "example.com",
            eventType,
            severity,
            scoreImpact,
            reporterTrustLevel,
            "Test reputation event.",
            createdAtUtc ?? DateTimeOffset.UtcNow,
            expiresAtUtc,
            isConfirmed,
            isAccidental);
}
