using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Tests.Rules;

/// <summary>Locks HIP-0404 simulation binding, independent approvals, and impact policy.</summary>
public sealed class RuleApprovalWorkflowTests
{
    [Test]
    public async Task Low_impact_is_ready_without_an_approval()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.Low);
        var simulation = await PassingSimulation(rule, simulations);

        var requested = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(requested.RequiredApprovalCount, Is.Zero);
            Assert.That(requested.Status, Is.EqualTo(RuleApprovalWorkflowStatus.ReadyForActivation));
            Assert.That(RuleApprovalWorkflowService.CanActivate(requested), Is.True);
        });
    }

    [Test]
    public async Task Medium_impact_requires_one_independent_approval_for_activation()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.Medium);
        var simulation = await PassingSimulation(rule, simulations);

        var requested = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);
        var approved = await service.ApproveAsync(requested.WorkflowId, "approver:1", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(requested.RequiredApprovalCount, Is.EqualTo(1));
            Assert.That(approved.Approvals, Has.Count.EqualTo(1));
            Assert.That(approved.Status, Is.EqualTo(RuleApprovalWorkflowStatus.ReadyForActivation));
            Assert.That(RuleApprovalWorkflowService.CanActivate(approved), Is.True);
        });
    }

    [Test]
    public async Task High_impact_requires_two_distinct_concurrent_approvers()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.High);
        var simulation = await PassingSimulation(rule, simulations);
        var requested = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);

        var approvals = await Task.WhenAll(
            service.ApproveAsync(requested.WorkflowId, "approver:1", CancellationToken.None),
            service.ApproveAsync(requested.WorkflowId, "approver:2", CancellationToken.None));
        var completed = approvals.OrderByDescending(value => value.Version).First();

        Assert.Multiple(() =>
        {
            Assert.That(completed.Approvals.Select(value => value.ApproverId),
                Is.EquivalentTo(new[] { "approver:1", "approver:2" }));
            Assert.That(completed.Status, Is.EqualTo(RuleApprovalWorkflowStatus.ReadyForActivation));
            Assert.That(RuleApprovalWorkflowService.CanActivate(completed), Is.True);
        });
    }

    [Test]
    public async Task Creator_duplicate_failed_and_stale_simulation_approvals_are_rejected()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.High);
        var simulation = await PassingSimulation(rule, simulations);
        var requested = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);
        await service.ApproveAsync(requested.WorkflowId, "approver:1", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(
                async () => await service.ApproveAsync(requested.WorkflowId, "creator:1", CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("creator"));
            Assert.That(
                async () => await service.ApproveAsync(requested.WorkflowId, "APPROVER:1", CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("already approved"));
            Assert.That(
                async () => await service.RequestAsync(rule with { Version = rule.Version + 1 }, simulation.SimulationId, CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("exact rule version"));
        });
    }

    [Test]
    public async Task Simulation_is_bound_to_the_exact_rule_definition_not_only_id_and_version()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.Medium);
        var simulation = await PassingSimulation(rule, simulations);
        var changedRule = rule with { Description = "Changed after simulation" };

        Assert.That(
            async () => await service.RequestAsync(changedRule, simulation.SimulationId, CancellationToken.None),
            Throws.InvalidOperationException.With.Message.Contains("exact rule version"));
    }

    [Test]
    public async Task Critical_impact_remains_blocked_after_two_approvals_until_manual_rollback_gate()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.Critical);
        var simulation = await PassingSimulation(rule, simulations);
        var requested = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);
        await service.ApproveAsync(requested.WorkflowId, "approver:1", CancellationToken.None);
        var approved = await service.ApproveAsync(requested.WorkflowId, "approver:2", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(approved.ManualDeploymentRequired, Is.True);
            Assert.That(approved.RollbackTestRequired, Is.True);
            Assert.That(approved.Status, Is.EqualTo(RuleApprovalWorkflowStatus.ApprovalSatisfied));
            Assert.That(RuleApprovalWorkflowService.CanActivate(approved), Is.False);
        });
    }

    [Test]
    public async Task Exact_rule_version_and_simulation_can_open_only_one_workflow()
    {
        var (service, simulations) = Workflow();
        var rule = Rule(RuleSeverity.High);
        var simulation = await PassingSimulation(rule, simulations);

        var first = await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(first.WorkflowId, Does.StartWith("rule-approval:"));
            Assert.That(
                async () => await service.RequestAsync(rule, simulation.SimulationId, CancellationToken.None),
                Throws.InvalidOperationException.With.Message.Contains("already exists"));
        });
    }

    [Test]
    public void Repository_rejects_inconsistent_workflow_state_before_persistence()
    {
        var repository = new InMemoryRuleApprovalWorkflowRepository(new InMemoryOutboxEventRepository());
        var invalid = new RuleApprovalWorkflowState(
            $"rule-approval:{new string('a', 32)}",
            "rule:1",
            1,
            "creator:1",
            "simulation:1",
            Rule(RuleSeverity.High) with { RuleId = "rule:1", Version = 1 },
            HipRuleImpactLevel.High,
            RequiredApprovalCount: 2,
            ManualDeploymentRequired: false,
            RollbackTestRequired: false,
            RollbackTestCompleted: false,
            ManualDeploymentAuthorized: false,
            RuleApprovalWorkflowStatus.ReadyForActivation,
            [],
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            Version: 1);
        var auditEvent = new HipDurableEvent(
            $"evt:{Guid.NewGuid():N}",
            "RuleApprovalRequested",
            "RuleApprovalWorkflow",
            invalid.WorkflowId,
            DateTimeOffset.UtcNow,
            "{}",
            HipDurableEventPrivacyLevel.PublicSafe);

        Assert.That(
            async () => await repository.TryCreateAsync(invalid, auditEvent, CancellationToken.None),
            Throws.ArgumentException.With.Message.Contains("status"));
    }

    private static (RuleApprovalWorkflowService Service, InMemoryRuleSimulationResultRepository Simulations) Workflow()
    {
        var simulations = new InMemoryRuleSimulationResultRepository();
        var repository = new InMemoryRuleApprovalWorkflowRepository(new InMemoryOutboxEventRepository());
        return (new RuleApprovalWorkflowService(repository, simulations), simulations);
    }

    private static async Task<RuleSimulationResult> PassingSimulation(
        TrustRule rule,
        IRuleSimulationResultRepository repository)
    {
        var simulation = new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine())).Simulate(
            rule,
            [new RuleSimulationTestCase(
                "matching fixture",
                new FactSet(new Dictionary<string, object?>
                {
                    ["domain.ageDays"] = 5,
                    ["url.usesShortener"] = true
                }),
                true,
                HIP.Domain.Risk.RiskStatus.HighRisk,
                true)]);
        await repository.SaveAsync(simulation.SimulationId, simulation, CancellationToken.None);
        return simulation;
    }

    private static TrustRule Rule(RuleSeverity severity) =>
        RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            Severity = severity,
            CreatedBy = "creator:1",
            Version = 3
        };
}
