using HIP.Security.Application.Policies.ActivatePolicy;
using HIP.Security.Application.Policies.CreatePolicyDraft;
using HIP.Security.Application.Policies.Internal;
using HIP.Security.Application.Policies.SimulatePolicy;
using HIP.Security.Domain.Approvals;
using HIP.Security.Domain.Policies;
using HIP.Security.Infrastructure.Repositories;

namespace HIP.Security.Tests;

public class PolicyDraftAndActivateTests
{
    [Test]
    public async Task DraftThenSimulateThenActivate_ShouldRequireExplicitPromotion()
    {
        var repository = new InMemoryPolicyRepository();
        var approvals = new InMemoryPolicyApprovalRepository();
        var audits = new InMemoryPolicyAuditRecorder();
        var draftHandler = new CreatePolicyDraftCommandHandler(repository, audits);
        var simulateHandler = new SimulatePolicyCommandHandler(repository, new PolicyLifecycleGuard(), audits);
        var activateHandler = new ActivatePolicyCommandHandler(repository, approvals, new PolicyLifecycleGuard(), audits);

        var draft = await draftHandler.Handle(
            new CreatePolicyDraftCommand(
                "Block replay attempts",
                "Placeholder policy",
                [new PolicyRule("request.nonce.age", ">", "30")]),
            CancellationToken.None);

        var simulated = await simulateHandler.Handle(new SimulatePolicyCommand(draft.Id), CancellationToken.None);
        var activated = await activateHandler.Handle(
            new ActivatePolicyCommand(
                draft.Id,
                new PolicyApprovalMetadata("author-1", "reviewer-1", "approver-1", "CHG-001", DateTimeOffset.UtcNow)),
            CancellationToken.None);

        Assert.That(simulated.LifecycleState, Is.EqualTo(PolicyLifecycleState.Simulate));
        Assert.That(activated.LifecycleState, Is.EqualTo(PolicyLifecycleState.Active));

        var persisted = await repository.GetByIdAsync(draft.Id, CancellationToken.None);
        Assert.That(persisted, Is.Not.Null);
        Assert.That(persisted!.LifecycleState, Is.EqualTo(PolicyLifecycleState.Active));
    }

    [Test]
    public async Task Activate_FromDraft_ShouldRejectWithReasonCode()
    {
        var repository = new InMemoryPolicyRepository();
        var approvals = new InMemoryPolicyApprovalRepository();
        var audits = new InMemoryPolicyAuditRecorder();
        var draftHandler = new CreatePolicyDraftCommandHandler(repository, audits);
        var activateHandler = new ActivatePolicyCommandHandler(repository, approvals, new PolicyLifecycleGuard(), audits);

        var draft = await draftHandler.Handle(
            new CreatePolicyDraftCommand("Draft", "Needs simulation", [new PolicyRule("k", "=", "v")]),
            CancellationToken.None);

        var ex = Assert.ThrowsAsync<PolicyTransitionRejectedException>(async () =>
            await activateHandler.Handle(
                new ActivatePolicyCommand(
                    draft.Id,
                    new PolicyApprovalMetadata("author-1", "reviewer-1", "approver-1", null, DateTimeOffset.UtcNow)),
                CancellationToken.None));

        Assert.That(ex!.ReasonCode, Is.EqualTo(PolicyTransitionRejectReasonCode.RequiresSimulationStage));
    }

    [Test]
    public void Activate_FromArchived_ShouldThrow()
    {
        var guard = new PolicyLifecycleGuard();
        var archived = new SecurityPolicy(
            Guid.NewGuid(),
            "Archived",
            "Cannot reactivate",
            PolicyLifecycleState.Archived,
            [],
            DateTimeOffset.UtcNow);

        var ex = Assert.Throws<PolicyTransitionRejectedException>(() => guard.TransitionToSimulate(archived));
        Assert.That(ex!.Message, Does.Contain("cannot move to Simulate"));
    }
}
