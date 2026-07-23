using HIP.Application.Reputation;
using HIP.Domain.Reputation;

namespace HIP.Tests.Reputation;

public sealed class AdminFeedbackServiceTests
{
    [Test]
    public async Task Overview_and_detail_expose_stored_evidence_without_private_identifiers()
    {
        var repository = new InMemoryWeightedFeedbackRepository();
        var aggregation = new WeightedFeedbackAggregationService(repository);
        var service = new AdminFeedbackService(repository, aggregation);
        var now = DateTimeOffset.UtcNow;

        await aggregation.SubmitAsync(Submission("Example.com", HipFeedbackType.LooksSafe, now.AddMinutes(-2)), CancellationToken.None);
        await aggregation.SubmitAsync(Submission("example.com", HipFeedbackType.LooksSuspicious, now.AddMinutes(-1)), CancellationToken.None);

        var overview = await service.GetOverviewAsync(CancellationToken.None);
        var detail = await service.GetDomainAsync("example.com", CancellationToken.None);
        var eventProperties = typeof(AdminFeedbackEvent).GetProperties().Select(property => property.Name).ToArray();

        Assert.Multiple(() =>
        {
            Assert.That(overview.TotalSubmissions, Is.EqualTo(2));
            Assert.That(overview.DistinctDomains, Is.EqualTo(1));
            Assert.That(overview.Domains.Single().SubmissionCount, Is.EqualTo(2));
            Assert.That(detail, Is.Not.Null);
            Assert.That(detail!.RecentEvents, Has.Count.EqualTo(2));
            Assert.That(detail.RecentEvents.First().FeedbackType, Is.EqualTo(HipFeedbackType.LooksSuspicious));
            Assert.That(eventProperties, Does.Not.Contain("ReporterHash"));
            Assert.That(eventProperties, Does.Not.Contain("PageUrlHash"));
            Assert.That(eventProperties, Does.Not.Contain("RawUrl"));
        });
    }

    [Test]
    public async Task Detail_returns_null_for_invalid_or_unknown_domain()
    {
        var repository = new InMemoryWeightedFeedbackRepository();
        var service = new AdminFeedbackService(repository, new WeightedFeedbackAggregationService(repository));
        var invalid = await service.GetDomainAsync("not a domain", CancellationToken.None);
        var unknown = await service.GetDomainAsync("unknown.example", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(invalid, Is.Null);
            Assert.That(unknown, Is.Null);
        });
    }

    [Test]
    public async Task Detail_keeps_older_stored_events_visible_without_counting_them_as_current_weight()
    {
        var repository = new InMemoryWeightedFeedbackRepository();
        await repository.SaveAsync(
            Submission("history.example", HipFeedbackType.ReportIssue, DateTimeOffset.UtcNow.AddDays(-30)),
            CancellationToken.None);
        var service = new AdminFeedbackService(repository, new WeightedFeedbackAggregationService(repository));

        var detail = await service.GetDomainAsync("history.example", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(detail, Is.Not.Null);
            Assert.That(detail!.Summary.RecentFeedbackCount, Is.Zero);
            Assert.That(detail.RecentEvents, Has.Count.EqualTo(1));
        });
    }

    private static WeightedFeedbackSubmission Submission(string domain, HipFeedbackType type, DateTimeOffset submittedAtUtc) =>
        new(
            domain,
            type,
            HipFeedbackSource.BrowserPluginPopup,
            ReporterTrustLevel.Verified,
            submittedAtUtc,
            "sha256:page-secret",
            "sha256:reporter-secret",
            "0.1.15-dev",
            HipFeedbackReasonCode.Other);
}
