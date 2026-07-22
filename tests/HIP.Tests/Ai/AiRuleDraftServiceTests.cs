using HIP.Application.Ai;
using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Tests.Ai;

/// <summary>Locks HIP-0406 immutable draft, simulation, and human-authority boundaries.</summary>
public sealed class AiRuleDraftServiceTests
{
    [Test]
    public async Task Low_impact_ai_output_is_persisted_as_a_simulated_disabled_draft()
    {
        var context = Context();

        var draft = await context.Drafts.CreateAsync(Request(), CancellationToken.None);
        var restored = await context.Repository.GetAsync(draft.DraftId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(restored, Is.EqualTo(draft));
            Assert.That(draft.ProposedRule.CreatorType, Is.EqualTo(HipRuleCreatorType.AiSuggested));
            Assert.That(draft.ProposedRule.Enabled, Is.False);
            Assert.That(draft.ProposedRule.Mode, Is.EqualTo(RuleMode.Disabled));
            Assert.That(draft.ProposedRule.RequiresApproval, Is.True);
            Assert.That(draft.SimulationPassed, Is.True);
            Assert.That(draft.PassedTestCount, Is.EqualTo(2));
            Assert.That(draft.FailedTestCount, Is.Zero);
        });
    }

    [Test]
    public async Task Ai_draft_requires_an_independent_human_approval_and_ai_actor_cannot_approve_or_deploy()
    {
        var context = Context();
        var draft = await context.Drafts.CreateAsync(Request(), CancellationToken.None);
        var workflow = await context.Drafts.SubmitForApprovalAsync(
            draft.DraftId, "human-submitter", CancellationToken.None);

        Assert.That(workflow.RequiredApprovalCount, Is.EqualTo(1));
        Assert.That(
            async () => await context.Approvals.ApproveAsync(
                workflow.WorkflowId, "ai:untrusted-model", CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("AI identities"));

        var approved = await context.Approvals.ApproveAsync(
            workflow.WorkflowId, "human-approver", CancellationToken.None);
        Assert.That(RuleApprovalWorkflowService.CanActivate(approved), Is.True);
        Assert.That(
            async () => await context.Deployments.ActivateAsync(
                workflow.WorkflowId, "ai:untrusted-model", "AI attempted deployment.", CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("AI identities"));
    }

    [Test]
    public void Private_or_secret_evidence_is_rejected_before_draft_persistence()
    {
        var context = Context();
        var request = Request() with
        {
            Analysis = Request().Analysis with { Reasons = ["password: must never be retained"] }
        };

        Assert.That(
            async () => await context.Drafts.CreateAsync(request, CancellationToken.None),
            Throws.ArgumentException.With.Message.Contains("privacy-safe"));
    }

    private static HipAiRuleSuggestionRequest Request() => new(
        "example.com",
        null,
        "Web",
        new HipAiRiskAnalysisResult(
            RiskStatus.Caution,
            55,
            ["One bounded urgency-language signal requires human review."],
            ["UrgencyLanguage"],
            "ShowCaution",
            RequiresReview: true,
            SuggestRule: true,
            IsPlaceholder: true,
            DevelopmentHipAiRiskAnalyzer.ProviderName));

    private static TestContext Context()
    {
        var simulations = new InMemoryRuleSimulationResultRepository();
        var outbox = new InMemoryOutboxEventRepository();
        var approvals = new RuleApprovalWorkflowService(
            new InMemoryRuleApprovalWorkflowRepository(outbox), simulations);
        var repository = new InMemoryAiRuleDraftRepository();
        var drafts = new AiRuleDraftService(
            new DevelopmentHipAiRiskAnalyzer(),
            new TrustRuleValidator(),
            new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine())),
            simulations,
            repository,
            approvals);
        var deployments = new RuleDeploymentService(
            new InMemoryRuleDeploymentRepository(outbox),
            new InMemoryRuleRepository(),
            approvals);
        return new TestContext(drafts, repository, approvals, deployments);
    }

    private sealed record TestContext(
        AiRuleDraftService Drafts,
        InMemoryAiRuleDraftRepository Repository,
        RuleApprovalWorkflowService Approvals,
        RuleDeploymentService Deployments);
}
