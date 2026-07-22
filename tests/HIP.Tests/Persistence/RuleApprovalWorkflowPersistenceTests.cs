using HIP.Application.Rules;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Rules;
using HIP.Infrastructure.Persistence;
using HIP.Infrastructure.Persistence.Repositories;
using HIP.Tests.Rules;
using Microsoft.EntityFrameworkCore;

namespace HIP.Tests.Persistence;

/// <summary>Verifies HIP-0404 encrypted CAS state and atomic actor-bound outbox events.</summary>
public sealed class RuleApprovalWorkflowPersistenceTests
{
    [Test]
    public async Task Concurrent_approvals_are_preserved_with_atomic_encrypted_audit_events()
    {
        var database = $"rule-approval-{Guid.NewGuid():N}";
        await using var setupContext = Context(database);
        var simulationRepository = new EfRuleSimulationResultRepository(Store(setupContext));
        var rule = RuleEngineTests.NewDomainShortenerRule(RuleMode.Watch) with
        {
            Severity = RuleSeverity.High,
            CreatedBy = "creator:1",
            Version = 4
        };
        var simulation = new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine())).Simulate(
            rule,
            [new RuleSimulationTestCase(
                "approval fixture",
                new FactSet(new Dictionary<string, object?>
                {
                    ["domain.ageDays"] = 5,
                    ["url.usesShortener"] = true
                }),
                true,
                HIP.Domain.Risk.RiskStatus.HighRisk,
                true)]);
        await simulationRepository.SaveAsync(simulation.SimulationId, simulation, CancellationToken.None);
        var setupService = new RuleApprovalWorkflowService(
            new EfRuleApprovalWorkflowRepository(Store(setupContext)),
            simulationRepository);
        var requested = await setupService.RequestAsync(rule, simulation.SimulationId, CancellationToken.None);

        await using var contextA = Context(database);
        await using var contextB = Context(database);
        var approvals = await Task.WhenAll(
            new RuleApprovalWorkflowService(
                    new EfRuleApprovalWorkflowRepository(Store(contextA)),
                    new EfRuleSimulationResultRepository(Store(contextA)))
                .ApproveAsync(requested.WorkflowId, "approver:1", CancellationToken.None),
            new RuleApprovalWorkflowService(
                    new EfRuleApprovalWorkflowRepository(Store(contextB)),
                    new EfRuleSimulationResultRepository(Store(contextB)))
                .ApproveAsync(requested.WorkflowId, "approver:2", CancellationToken.None));

        await using var verifyContext = Context(database);
        var store = Store(verifyContext);
        var final = await new EfRuleApprovalWorkflowRepository(store).GetAsync(requested.WorkflowId, CancellationToken.None);
        var events = await new EfOutboxEventRepository(store).ListPendingAsync(10, CancellationToken.None);
        var rows = await verifyContext.Records.AsNoTracking().ToArrayAsync();

        Assert.Multiple(() =>
        {
            Assert.That(approvals, Has.Length.EqualTo(2));
            Assert.That(final!.Approvals.Select(value => value.ApproverId),
                Is.EquivalentTo(new[] { "approver:1", "approver:2" }));
            Assert.That(final.Version, Is.EqualTo(3));
            Assert.That(events, Has.Count.EqualTo(3));
            Assert.That(rows, Has.All.Matches<HipDbRecord>(row =>
                new DevelopmentHipRecordEncryptor().IsProtectedPayload(row.Json)));
            Assert.That(rows.Select(row => row.Json), Has.None.Contains("approver:1"));
        });
    }

    private static HipDbContext Context(string database) =>
        new(new DbContextOptionsBuilder<HipDbContext>().UseInMemoryDatabase(database).Options);

    private static HipRecordStore Store(HipDbContext context) =>
        new(context, new DevelopmentHipRecordEncryptor());
}
