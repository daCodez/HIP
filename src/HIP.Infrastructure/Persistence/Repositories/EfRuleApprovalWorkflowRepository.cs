using HIP.Application.Rules;
using HIP.Application.Scalability;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Encrypted CAS approval state with an atomic actor-bound outbox audit event.</summary>
public sealed class EfRuleApprovalWorkflowRepository(HipRecordStore store) : IRuleApprovalWorkflowRepository
{
    private const string Partition = "rule-approval-workflow";
    private const string OutboxPartition = "outbox-event";

    public Task<bool> TryCreateAsync(
        RuleApprovalWorkflowState state,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion: 0, auditEvent, cancellationToken);

    public async Task<RuleApprovalWorkflowState?> GetAsync(string workflowId, CancellationToken cancellationToken)
    {
        if (!RuleApprovalWorkflowContract.IsCanonicalWorkflowId(workflowId)) return null;
        var stored = await store.GetVersionedAsync<RuleApprovalWorkflowState>(Partition, workflowId, cancellationToken);
        if (stored is null) return null;
        if (stored.Value.Record.Version != stored.Value.AggregateVersion)
            throw new InvalidOperationException("Rule approval workflow version is inconsistent.");
        RuleApprovalWorkflowContract.Validate(stored.Value.Record);
        return stored.Value.Record;
    }

    public Task<bool> TryUpdateAsync(
        RuleApprovalWorkflowState state,
        long expectedVersion,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion, auditEvent, cancellationToken);

    private Task<bool> SaveAsync(
        RuleApprovalWorkflowState state,
        long expectedVersion,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(auditEvent);
        RuleApprovalWorkflowContract.Validate(state);
        if (state.Version != expectedVersion + 1 ||
            auditEvent.AggregateId != state.WorkflowId)
        {
            throw new ArgumentException("Rule approval transition metadata is inconsistent.", nameof(state));
        }
        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            state.WorkflowId,
            state,
            expectedVersion,
            state.Version,
            [new HipRelatedRecordWrite<HipDurableEvent>(OutboxPartition, auditEvent.EventId, auditEvent)],
            cancellationToken);
    }

}
