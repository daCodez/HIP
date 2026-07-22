using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

/// <summary>Locks HIP-0405 exact-workflow activation and one-action rollback behavior.</summary>
public sealed class RuleDeploymentServiceTests
{
    [Test]
    public async Task High_impact_activation_starts_in_watch_mode_and_first_rollback_target_is_disabled()
    {
        var context = Context();
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            Severity = RuleSeverity.High,
            CreatedBy = "creator:1",
            Version = 3
        };
        await context.Rules.SaveAsync(rule, CancellationToken.None);
        var workflow = await ApprovedWorkflow(context, rule);

        var deployed = await context.Deployments.ActivateAsync(
            workflow.WorkflowId, "deployer:1", "Initial controlled deployment.", CancellationToken.None);
        var promoted = await context.Deployments.PromoteAsync(
            rule.RuleId, deployed.Version, "deployer:2", "Watch validation passed.", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(deployed.ActiveRule!.Version, Is.EqualTo(3));
            Assert.That(deployed.ActiveRule.Mode, Is.EqualTo(RuleMode.Watch));
            Assert.That(deployed.RollbackRule, Is.Null);
            Assert.That(deployed.UseDisabledRollback, Is.True);
            Assert.That(deployed.RollbackAvailable, Is.True);
            Assert.That(promoted.ActiveRule!.Mode, Is.EqualTo(RuleMode.Active));
            Assert.That(promoted.Status, Is.EqualTo(RuleDeploymentStatus.Active));
            Assert.That(promoted.RollbackAvailable, Is.True);
        });
    }

    [Test]
    public async Task New_version_can_roll_back_once_to_exact_prior_active_snapshot()
    {
        var context = Context();
        var firstRule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            Severity = RuleSeverity.Medium,
            CreatedBy = "creator:1",
            Version = 1
        };
        await context.Rules.SaveAsync(firstRule, CancellationToken.None);
        var firstWorkflow = await ApprovedWorkflow(context, firstRule);
        await context.Deployments.ActivateAsync(
            firstWorkflow.WorkflowId, "deployer:1", "Initial deployment.", CancellationToken.None);

        var secondRule = firstRule with { Version = 2, Description = "Second immutable version." };
        await context.Rules.SaveAsync(secondRule, CancellationToken.None);
        var secondWorkflow = await ApprovedWorkflow(context, secondRule);
        var secondDeployment = await context.Deployments.ActivateAsync(
            secondWorkflow.WorkflowId, "deployer:2", "Deploy version two.", CancellationToken.None);

        var rolledBack = await context.Deployments.RollbackAsync(
            firstRule.RuleId, secondDeployment.Version, "rollback:1", "Observed false positives.", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(secondDeployment.RollbackRule!.Version, Is.EqualTo(1));
            Assert.That(rolledBack.ActiveRule!.Version, Is.EqualTo(1));
            Assert.That(rolledBack.RollbackAvailable, Is.False);
            Assert.That(
                async () => await context.Deployments.RollbackAsync(
                    firstRule.RuleId, rolledBack.Version, "rollback:1", "Replay.", CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("not available"));
        });
    }

    [Test]
    public async Task Stale_workflow_cannot_activate_after_a_new_rule_version_is_saved()
    {
        var context = Context();
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            Severity = RuleSeverity.Medium,
            CreatedBy = "creator:1",
            Version = 1
        };
        await context.Rules.SaveAsync(rule, CancellationToken.None);
        var workflow = await ApprovedWorkflow(context, rule);
        await context.Rules.SaveAsync(rule with { Version = 2 }, CancellationToken.None);

        Assert.That(
            async () => await context.Deployments.ActivateAsync(
                workflow.WorkflowId, "deployer:1", "Stale deployment.", CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("stale"));
    }

    [Test]
    public async Task Critical_activation_requires_rollback_test_and_manual_deployment_authorization()
    {
        var context = Context();
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Active) with
        {
            Severity = RuleSeverity.Critical,
            CreatedBy = "creator:1",
            Version = 1
        };
        await context.Rules.SaveAsync(rule, CancellationToken.None);
        var workflow = await ApprovedWorkflow(context, rule);

        Assert.That(
            async () => await context.Deployments.ActivateAsync(
                workflow.WorkflowId, "deployer:1", "Too early.", CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("cannot activate"));

        await context.Approvals.CompleteRollbackTestAsync(
            workflow.WorkflowId, "tester:1", "Rollback drill passed.", CancellationToken.None);
        await context.Approvals.AuthorizeManualDeploymentAsync(
            workflow.WorkflowId, "deployer:1", "Approved deployment window.", CancellationToken.None);
        var deployed = await context.Deployments.ActivateAsync(
            workflow.WorkflowId, "deployer:1", "Manual critical deployment.", CancellationToken.None);

        Assert.That(deployed.ActiveRule!.Version, Is.EqualTo(1));
    }

    private static async Task<RuleApprovalWorkflowState> ApprovedWorkflow(TestContext context, TrustRule rule)
    {
        var simulation = new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine())).Simulate(
            rule,
            [new RuleSimulationTestCase(
                "deployment fixture",
                new FactSet(new Dictionary<string, object?>
                {
                    ["domain.ageDays"] = 5,
                    ["url.usesShortener"] = true
                }),
                true,
                HIP.Domain.Risk.RiskStatus.HighRisk,
                true)]);
        await context.Simulations.SaveAsync(simulation.SimulationId, simulation, CancellationToken.None);
        var workflow = await context.Approvals.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);
        if (workflow.RequiredApprovalCount >= 1)
            workflow = await context.Approvals.ApproveAsync(workflow.WorkflowId, "approver:1", CancellationToken.None);
        if (workflow.RequiredApprovalCount >= 2)
            workflow = await context.Approvals.ApproveAsync(workflow.WorkflowId, "approver:2", CancellationToken.None);
        return workflow;
    }

    private static TestContext Context()
    {
        var outbox = new InMemoryOutboxEventRepository();
        var simulations = new InMemoryRuleSimulationResultRepository();
        var approvals = new RuleApprovalWorkflowService(
            new InMemoryRuleApprovalWorkflowRepository(outbox), simulations);
        var rules = new InMemoryRuleRepository();
        var deployments = new RuleDeploymentService(
            new InMemoryRuleDeploymentRepository(outbox), rules, approvals);
        return new TestContext(rules, simulations, approvals, deployments);
    }

    private sealed record TestContext(
        InMemoryRuleRepository Rules,
        InMemoryRuleSimulationResultRepository Simulations,
        RuleApprovalWorkflowService Approvals,
        RuleDeploymentService Deployments);
}
