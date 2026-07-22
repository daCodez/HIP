using System.Net.Http.Json;
using System.Text.Json;
using HIP.Application.Identity;
using HIP.Application.Review;
using HIP.Domain.Audit;
using HIP.Domain.Identity;
using HIP.Domain.Review;
using HIP.Domain.Risk;
using HIP.Web.Security;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace HIP.Tests.Security;

[TestFixture]
public sealed class AdministrativeActorBindingTests
{
    private const string AuthenticatedActor = "authenticated-review-owner";

    [Test]
    public async Task Website_verification_retry_audit_uses_the_unique_authenticated_HIP_actor()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = CreateOwnerClient(factory);
        var domain = $"actor-bound-retry-{Guid.NewGuid():N}.example";
        var registration = await client.PostAsJsonAsync(
            "/api/v1/identity/websites/register",
            new WebsiteIdentityRegistrationRequest(domain, "Actor-bound retry", VerificationMethod.DnsTxt));
        await ReadSuccessfulResponseAsync<WebsiteIdentityRegistrationResponse>(registration);

        var retry = await client.PostAsync($"/api/v1/identity/websites/{domain}/retry", content: null);
        await ReadSuccessfulResponseAsync<WebsiteIdentity>(retry);

        var audit = await client.GetFromJsonAsync<IReadOnlyCollection<AuditLogEntry>>(
            "/api/v1/admin/audit-logs");
        var retryEntry = audit!.Single(entry =>
            entry.TargetId == domain && entry.Action == "domain-verification.retried");

        Assert.That(retryEntry.ActorId, Is.EqualTo(AuthenticatedActor));
    }

    [Test]
    public async Task Review_creation_and_decisions_ignore_forged_actor_and_system_fields()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var client = CreateOwnerClient(factory);
        var target = $"review-binding-{Guid.NewGuid():N}.example";
        var forged = new ReviewItem(
            "forged-review-id",
            ReviewType.RiskyDomain,
            TargetType.Domain,
            target,
            "Review actor binding",
            "Privacy-safe administrative actor-binding regression.",
            RiskStatus.HighRisk,
            ReviewStatus.Closed,
            ReviewPriority.High,
            DateTimeOffset.UtcNow.AddYears(-2),
            DateTimeOffset.UtcNow.AddYears(-2),
            "forged-creator",
            "forged-assignee",
            "admin-test",
            "Privacy-safe evidence only.",
            new Dictionary<string, string> { ["signal"] = "actor-binding" },
            "Review the signal.",
            "forged-decision",
            "forged-decision-reason");

        var createResponse = await client.PostAsJsonAsync("/api/v1/admin/review/", forged);
        var created = await ReadSuccessfulResponseAsync<ReviewItem>(createResponse);

        Assert.Multiple(() =>
        {
            Assert.That(created.ReviewItemId, Is.Not.EqualTo("forged-review-id"));
            Assert.That(created.CreatedBy, Is.EqualTo(AuthenticatedActor));
            Assert.That(created.Status, Is.EqualTo(ReviewStatus.Submitted));
            Assert.That(created.AssignedTo, Is.Null);
            Assert.That(created.Decision, Is.Null);
            Assert.That(created.DecisionReason, Is.Null);
            Assert.That(created.CreatedAtUtc, Is.GreaterThan(DateTimeOffset.UtcNow.AddMinutes(-1)));
        });

        var approveResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/review/{created.ReviewItemId}/approve",
            new { ActorId = "forged-reviewer", Reason = "Approved after review." });
        await ReadSuccessfulResponseAsync<ReviewItem>(approveResponse);

        var audit = await client.GetFromJsonAsync<IReadOnlyCollection<AuditLogEntry>>(
            "/api/v1/admin/audit-logs");
        var approvalEntry = audit!.Single(entry =>
            entry.TargetId == target && entry.Action == "Review item approved");
        Assert.That(approvalEntry.ActorId, Is.EqualTo(AuthenticatedActor));
    }

    [Test]
    public async Task Appeal_decisions_ignore_forged_reviewer()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        using var publicClient = factory.CreateClient();
        var target = $"appeal-binding-{Guid.NewGuid():N}.example";
        var appeal = new AppealRequest(
            string.Empty,
            TargetType.Domain,
            target,
            "sha256:test-submitter",
            "The domain owner supplied a privacy-safe remediation summary.",
            AppealStatus.Submitted,
            default,
            default,
            null,
            null,
            null,
            new Dictionary<string, string> { ["summary"] = "remediation-complete" });
        var submitResponse = await publicClient.PostAsJsonAsync("/api/v1/public/appeals", appeal);
        var submitted = await ReadSuccessfulResponseAsync<AppealRequest>(submitResponse);

        using var ownerClient = CreateOwnerClient(factory);
        var approveResponse = await ownerClient.PostAsJsonAsync(
            $"/api/v1/admin/appeals/{submitted.AppealId}/approve",
            new { ActorId = "forged-appeal-reviewer", Reason = "Remediation verified." });
        var approved = await ReadSuccessfulResponseAsync<AppealRequest>(approveResponse);

        Assert.That(approved.ReviewerId, Is.EqualTo(AuthenticatedActor));
        var audit = await ownerClient.GetFromJsonAsync<IReadOnlyCollection<AuditLogEntry>>(
            "/api/v1/admin/audit-logs");
        var approvalEntry = audit!.Single(entry =>
            entry.TargetId == target && entry.Action == "Appeal approved");
        Assert.That(approvalEntry.ActorId, Is.EqualTo(AuthenticatedActor));
    }

    [Test]
    public async Task Admin_review_queue_assignment_decision_and_dismissal_ignore_forged_actors()
    {
        await using var factory = new HipWebApplicationFactory<Program>();
        var decisionItem = await CreateAdminReviewSignalAsync(factory, $"decision-{Guid.NewGuid():N}.example");
        var dismissalItem = await CreateAdminReviewSignalAsync(factory, $"dismiss-{Guid.NewGuid():N}.example");
        using var client = CreateOwnerClient(factory);

        var assignResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/review-queue/{decisionItem.ReviewId}/assign",
            new { ActorId = "forged-assigner", AssignedTo = "privacy-safe-reviewer-alias" });
        await ReadSuccessfulResponseAsync<AdminReviewQueueItem>(assignResponse);

        var decisionResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/review-queue/{decisionItem.ReviewId}/decision",
            new
            {
                Decision = AdminReviewDecision.ConfirmHighRisk,
                DecisionReason = "Confirmed from privacy-safe evidence.",
                ReviewedBy = "forged-decision-reviewer"
            });
        var decided = await ReadSuccessfulResponseAsync<AdminReviewQueueItem>(decisionResponse);

        var dismissResponse = await client.PostAsJsonAsync(
            $"/api/v1/admin/review-queue/{dismissalItem.ReviewId}/dismiss",
            new { ActorId = "forged-dismiss-reviewer", Reason = "Duplicate signal." });
        var dismissed = await ReadSuccessfulResponseAsync<AdminReviewQueueItem>(dismissResponse);

        Assert.Multiple(() =>
        {
            Assert.That(decided.ReviewedBy, Is.EqualTo(AuthenticatedActor));
            Assert.That(dismissed.ReviewedBy, Is.EqualTo(AuthenticatedActor));
        });

        var audit = await client.GetFromJsonAsync<IReadOnlyCollection<AuditLogEntry>>(
            "/api/v1/admin/audit-logs");
        var entries = audit ?? throw new AssertionException("Expected audit entries.");
        Assert.Multiple(() =>
        {
            Assert.That(entries.Single(entry =>
                entry.TargetId == decisionItem.Domain && entry.Action == "Admin review item assigned").ActorId,
                Is.EqualTo(AuthenticatedActor));
            Assert.That(entries.Single(entry =>
                entry.TargetId == decisionItem.Domain && entry.Action == "Admin review decision recorded").ActorId,
                Is.EqualTo(AuthenticatedActor));
            Assert.That(entries.Single(entry =>
                entry.TargetId == dismissalItem.Domain && entry.Action == "Admin review item dismissed").ActorId,
                Is.EqualTo(AuthenticatedActor));
        });
    }

    private static async Task<AdminReviewQueueItem> CreateAdminReviewSignalAsync(
        HipWebApplicationFactory<Program> factory,
        string domain)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<IAdminReviewQueueService>();
        return await service.CreateSignalAsync(
            new AdminReviewSignal(
                domain,
                null,
                AdminReviewTargetType.Domain,
                "actor-binding",
                AdminReviewSeverity.Medium,
                AdminReviewSource.System,
                null,
                null,
                null,
                45,
                "Review",
                "Medium",
                "Privacy-safe actor-binding review signal.",
                "Privacy-safe evidence summary."),
            CancellationToken.None);
    }

    private static HttpClient CreateOwnerClient(HipWebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-HIP-Admin-Role", AdminRoles.Owner);
        client.DefaultRequestHeaders.Add("X-HIP-Admin-User", AuthenticatedActor);
        return client;
    }

    private static async Task<T> ReadSuccessfulResponseAsync<T>(HttpResponseMessage response)
        where T : class
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.That(response.IsSuccessStatusCode, Is.True, body);
        return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new AssertionException($"Expected a {typeof(T).Name} response body.");
    }
}
