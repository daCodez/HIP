using FluentValidation;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Review;
using HIP.Domain.Risk;

namespace HIP.Tests.Review;

public sealed class ReviewFlowTests
{
    [Test]
    public void Review_item_can_be_created()
    {
        var services = Services();

        var created = services.ReviewQueue.Create(ReviewItem());

        Assert.That(created.ReviewItemId, Is.Not.Empty);
        Assert.That(created.Status, Is.EqualTo(ReviewStatus.Submitted));
        Assert.That(services.ReviewQueue.List(), Has.Count.EqualTo(1));
    }

    [Test]
    public void Review_item_can_be_approved()
    {
        var services = Services();
        var created = services.ReviewQueue.Create(ReviewItem());

        var approved = services.ReviewQueue.Approve(created.ReviewItemId, "admin", "Evidence supports action.");

        Assert.That(approved.Status, Is.EqualTo(ReviewStatus.Confirmed));
        Assert.That(approved.Decision, Is.EqualTo("Approved"));
    }

    [Test]
    public void Review_item_can_be_rejected()
    {
        var services = Services();
        var created = services.ReviewQueue.Create(ReviewItem());

        var rejected = services.ReviewQueue.Reject(created.ReviewItemId, "admin", "Insufficient evidence.");

        Assert.That(rejected.Status, Is.EqualTo(ReviewStatus.Rejected));
        Assert.That(rejected.Decision, Is.EqualTo("Rejected"));
    }

    [Test]
    public void Appeal_can_be_submitted()
    {
        var services = Services();

        var appeal = services.Appeals.Submit(Appeal());

        Assert.That(appeal.AppealId, Is.Not.Empty);
        Assert.That(appeal.Status, Is.EqualTo(AppealStatus.Submitted));
    }

    [Test]
    public void Appeal_status_can_be_viewed()
    {
        var services = Services();
        var appeal = services.Appeals.Submit(Appeal());

        var found = services.Appeals.Get(appeal.AppealId);

        Assert.That(found, Is.Not.Null);
        Assert.That(found!.Status, Is.EqualTo(AppealStatus.Submitted));
    }

    [Test]
    public void False_positive_item_is_supported()
    {
        var services = Services();
        var falsePositive = ReviewItem() with
        {
            ReviewType = ReviewType.FalsePositive,
            Title = "Review false positive report",
            Summary = "Reporter says this domain was incorrectly flagged."
        };

        var created = services.ReviewQueue.Create(falsePositive);

        Assert.That(created.ReviewType, Is.EqualTo(ReviewType.FalsePositive));
    }

    [Test]
    public void Appeal_can_be_approved()
    {
        var services = Services();
        var appeal = services.Appeals.Submit(Appeal());

        var approved = services.Appeals.Approve(appeal.AppealId, "moderator", "Remediation verified.");

        Assert.That(approved.Status, Is.EqualTo(AppealStatus.Approved));
        Assert.That(approved.Decision, Is.EqualTo("Approved"));
    }

    [Test]
    public void Appeal_can_be_rejected()
    {
        var services = Services();
        var appeal = services.Appeals.Submit(Appeal());

        var rejected = services.Appeals.Reject(appeal.AppealId, "moderator", "Risk evidence remains.");

        Assert.That(rejected.Status, Is.EqualTo(AppealStatus.Rejected));
        Assert.That(rejected.Decision, Is.EqualTo("Rejected"));
    }

    [Test]
    public void Reputation_override_request_calculates_required_approvals()
    {
        var services = Services();

        var request = services.Overrides.Request(Override(currentScore: 70, requestedScore: 76));

        Assert.That(request.RequiredApprovalCount, Is.EqualTo(1));
    }

    [Test]
    public void Large_score_changes_require_two_approvals()
    {
        var services = Services();

        var request = services.Overrides.Request(Override(currentScore: 45, requestedScore: 80));

        Assert.That(request.RequiredApprovalCount, Is.EqualTo(2));
    }

    [Test]
    public void Trusted_from_dangerous_requires_two_approvals()
    {
        var services = Services();

        var request = services.Overrides.Request(Override(currentScore: 18, requestedScore: 88));

        Assert.That(request.RequiredApprovalCount, Is.EqualTo(2));
    }

    [Test]
    public void Override_does_not_apply_until_approval_requirements_are_met()
    {
        var services = Services();
        var request = services.Overrides.Request(Override(currentScore: 15, requestedScore: 90));

        var firstApproval = services.Overrides.Approve(request.OverrideRequestId, "admin-one", "First approval.");

        Assert.That(firstApproval.Status, Is.EqualTo(OverrideRequestStatus.Pending));
        Assert.That(firstApproval.Approvals.Count, Is.EqualTo(1));

        var secondApproval = services.Overrides.Approve(request.OverrideRequestId, "admin-two", "Second approval.");

        Assert.That(secondApproval.Status, Is.EqualTo(OverrideRequestStatus.Approved));
        Assert.That(secondApproval.Approvals.Count, Is.EqualTo(2));
    }

    [Test]
    public void Audit_log_is_created_for_review_decisions()
    {
        var services = Services();
        var created = services.ReviewQueue.Create(ReviewItem());

        services.ReviewQueue.Approve(created.ReviewItemId, "admin", "Approved.");

        Assert.That(services.AuditLogs.List().Any(entry => entry.Action == "Review item approved"), Is.True);
    }

    [Test]
    public void Audit_log_is_created_for_reputation_override_decisions()
    {
        var services = Services();
        var request = services.Overrides.Request(Override(currentScore: 75, requestedScore: 82));

        services.Overrides.Approve(request.OverrideRequestId, "owner", "Approved.");

        Assert.That(services.AuditLogs.List().Any(entry => entry.Action == "Reputation override approved"), Is.True);
        Assert.That(services.AuditLogs.List().Any(entry => entry.Action == "Manual reputation change applied"), Is.True);
    }

    [Test]
    public void Private_chat_content_is_not_required_by_review_or_appeal_models()
    {
        var review = ReviewItem();
        var appeal = Appeal();

        Assert.That(review.PrivacySafeEvidence.Keys, Does.Not.Contain("privateChatLog"));
        Assert.That(appeal.PrivacySafeEvidence.Keys, Does.Not.Contain("privateChatLog"));
        Assert.That(typeof(ReviewItem).GetProperties().Select(property => property.Name), Does.Not.Contain("PrivateChatLog"));
        Assert.That(typeof(AppealRequest).GetProperties().Select(property => property.Name), Does.Not.Contain("PrivateChatLog"));
    }

    [Test]
    public void Validation_rejects_invalid_score_values()
    {
        var services = Services();

        Assert.Throws<ValidationException>(() => services.Overrides.Request(Override(currentScore: -1, requestedScore: 105)));
    }

    private static ServiceSet Services()
    {
        var audit = new AuditLogService();
        return new ServiceSet(
            new ReviewQueueService(new ReviewItemValidator(), audit),
            new AppealService(new AppealRequestValidator(), audit),
            new ReputationOverrideService(new ReputationOverrideRequestValidator(), audit),
            audit);
    }

    private static ReviewItem ReviewItem() => new(
        "",
        ReviewType.RiskyDomain,
        TargetType.Domain,
        "suspicious.example",
        "Review suspicious domain",
        "Repeated privacy-safe suspicious findings.",
        RiskStatus.HighRisk,
        ReviewStatus.Submitted,
        ReviewPriority.High,
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow,
        "system",
        null,
        "self-healing",
        "URL hash and risk reason only.",
        new Dictionary<string, string> { ["urlHash"] = "sha256:sample" },
        "Keep in watch mode pending review.",
        null,
        null);

    private static AppealRequest Appeal() => new(
        "",
        TargetType.Domain,
        "appeal.example",
        "sha256:submitter",
        "The domain owner corrected the issue.",
        AppealStatus.Submitted,
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow,
        null,
        null,
        null,
        new Dictionary<string, string> { ["evidenceSummary"] = "public remediation note" });

    private static ReputationOverrideRequest Override(int currentScore, int requestedScore) => new(
        "",
        TargetType.Domain,
        "override.example",
        currentScore,
        requestedScore,
        "Manual correction request.",
        "admin",
        OverrideRequestStatus.Pending,
        1,
        [],
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow);

    private sealed record ServiceSet(
        IReviewQueueService ReviewQueue,
        IAppealService Appeals,
        IReputationOverrideService Overrides,
        IAuditLogService AuditLogs);
}
