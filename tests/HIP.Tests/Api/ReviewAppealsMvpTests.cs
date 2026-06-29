using System.Net;
using System.Net.Http.Json;
using HIP.Application.Consumer;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using Microsoft.AspNetCore.Mvc.Testing;

namespace HIP.Tests.Api;

public sealed class ReviewAppealsMvpTests
{
    [Test]
    public async Task Review_list_returns_privacy_safe_items()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var created = await CreateReviewAsync(client);

        var body = await client.GetStringAsync("/api/v1/admin/review");

        Assert.That(created.ReviewItemId, Is.Not.Empty);
        Assert.That(body, Does.Contain("Privacy-safe summary."));
        Assert.That(body, Does.Not.Contain("private chat content"));
        Assert.That(body, Does.Not.Contain("raw private message"));
    }

    [Test]
    public async Task Review_decision_updates_status()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);
        var created = await CreateReviewAsync(client);

        var response = await client.PostAsJsonAsync($"/api/v1/admin/review/{created.ReviewItemId}/decision", new
        {
            ActorId = "moderator-test",
            Status = ReviewStatus.Confirmed,
            Reason = "Privacy-safe evidence confirms the finding."
        });
        var updated = await response.Content.ReadFromJsonAsync<ReviewItem>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(updated!.Status, Is.EqualTo(ReviewStatus.Confirmed));
        Assert.That(updated.DecisionReason, Does.Contain("confirms"));
    }

    [Test]
    public async Task Appeal_can_be_submitted_and_viewed_by_consumer()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = ConsumerClient(factory);

        var response = await client.PostAsJsonAsync("/api/v1/consumer/appeals", new ConsumerAppealSubmissionRequest(
            TargetType.Domain,
            "appeal.example",
            "Risk was remediated using public DNS and redirect changes.",
            new Dictionary<string, string> { ["evidenceSummary"] = "public remediation note" }));
        var submitted = await response.Content.ReadFromJsonAsync<ConsumerAppealSubmissionResult>();
        var appeals = await client.GetFromJsonAsync<IReadOnlyCollection<ConsumerAppealItem>>("/api/v1/consumer/appeals");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(submitted!.Accepted, Is.True);
        Assert.That(appeals!.Any(appeal => appeal.AppealId == submitted.AppealId), Is.True);
    }

    [Test]
    public async Task Appeal_decision_updates_status()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var consumer = ConsumerClient(factory);
        var submitted = await SubmitAppealAsync(consumer);
        using var admin = AdminClient(factory);

        var response = await admin.PostAsJsonAsync($"/api/v1/admin/appeals/{submitted.AppealId}/decision", new
        {
            ActorId = "moderator-test",
            Status = AppealStatus.Approved,
            Reason = "Appeal evidence is sufficient."
        });
        var updated = await response.Content.ReadFromJsonAsync<AppealRequest>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(updated!.Status, Is.EqualTo(AppealStatus.Approved));
    }

    [Test]
    public async Task Admin_review_routes_are_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/review");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Generated_review_queue_route_is_protected()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/admin/review-queue");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Authorized_admin_can_list_generated_review_queue()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = AdminClient(factory);

        var response = await client.GetAsync("/api/v1/admin/review-queue");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Consumer_appeal_response_does_not_expose_private_reviewer_data()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var consumer = ConsumerClient(factory);
        var submitted = await SubmitAppealAsync(consumer);
        using var admin = AdminClient(factory);
        await admin.PostAsJsonAsync($"/api/v1/admin/appeals/{submitted.AppealId}/decision", new
        {
            ActorId = "private-reviewer-id",
            Status = AppealStatus.NeedsMoreInfo,
            Reason = "Need public evidence."
        });

        var body = await consumer.GetStringAsync("/api/v1/consumer/appeals");

        Assert.That(body, Does.Contain(submitted.AppealId));
        Assert.That(body, Does.Not.Contain("private-reviewer-id"));
        Assert.That(body, Does.Not.Contain("ReviewerId"));
    }

    private static async Task<ReviewItem> CreateReviewAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/api/v1/admin/review", new ReviewItem(
            "",
            ReviewType.RiskyDomain,
            TargetType.Domain,
            "risky-review.example",
            "Review risky domain",
            "Privacy-safe summary.",
            RiskStatus.HighRisk,
            ReviewStatus.Submitted,
            ReviewPriority.High,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            "test",
            null,
            "test",
            "URL hash and domain only.",
            new Dictionary<string, string> { ["urlHash"] = "sha256:review" },
            "Confirm or reject finding.",
            null,
            null));

        return (await response.Content.ReadFromJsonAsync<ReviewItem>())!;
    }

    private static async Task<ConsumerAppealSubmissionResult> SubmitAppealAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/api/v1/consumer/appeals", new ConsumerAppealSubmissionRequest(
            TargetType.Domain,
            "appeal-review.example",
            "This target was remediated.",
            new Dictionary<string, string> { ["evidenceSummary"] = "public remediation note" }));

        return (await response.Content.ReadFromJsonAsync<ConsumerAppealSubmissionResult>())!;
    }

    private static HttpClient AdminClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", "Moderator");
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", "review-mvp-test");
        return client;
    }

    private static HttpClient ConsumerClient(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Consumer-Id", "consumer-appeal-test");
        return client;
    }
}
