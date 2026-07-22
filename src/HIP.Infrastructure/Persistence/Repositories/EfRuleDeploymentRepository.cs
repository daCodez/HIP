using HIP.Application.Rules;
using HIP.Application.Scalability;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>Encrypted CAS deployment state with atomic transition audit events.</summary>
public sealed class EfRuleDeploymentRepository(HipRecordStore store) : IRuleDeploymentRepository
{
    private const string Partition = "rule-deployment";
    private const string OutboxPartition = "outbox-event";

    public async Task<RuleDeploymentState?> GetAsync(string ruleId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ruleId) || ruleId.Length > 160 || ruleId.Any(char.IsControl)) return null;
        var id = RuleDeploymentContract.DeploymentId(ruleId);
        var stored = await store.GetVersionedAsync<RuleDeploymentState>(Partition, id, cancellationToken);
        if (stored is null || stored.Value.Record is null) return null;
        if (stored.Value.Record.Version != stored.Value.AggregateVersion)
            throw new InvalidOperationException("Rule deployment version is inconsistent.");
        RuleDeploymentContract.Validate(stored.Value.Record);
        return stored.Value.Record;
    }

    public async Task<IReadOnlyCollection<RuleDeploymentState>> ListAsync(CancellationToken cancellationToken)
    {
        var states = await store.ListAsync<RuleDeploymentState>(Partition, cancellationToken);
        foreach (var state in states) RuleDeploymentContract.Validate(state);
        return states.OrderBy(state => state.RuleId, StringComparer.Ordinal).ToArray();
    }

    public Task<bool> TryCreateAsync(
        RuleDeploymentState state,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion: 0, auditEvent, cancellationToken);

    public Task<bool> TryUpdateAsync(
        RuleDeploymentState state,
        long expectedVersion,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion, auditEvent, cancellationToken);

    private Task<bool> SaveAsync(
        RuleDeploymentState state,
        long expectedVersion,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken)
    {
        RuleDeploymentContract.Validate(state);
        ArgumentNullException.ThrowIfNull(auditEvent);
        if (state.Version != expectedVersion + 1 || auditEvent.AggregateId != state.DeploymentId)
            throw new ArgumentException("Rule deployment transition metadata is inconsistent.", nameof(state));
        return store.TrySaveVersionedWithRelatedRecordsAsync(
            Partition,
            state.DeploymentId,
            state,
            expectedVersion,
            state.Version,
            [new HipRelatedRecordWrite<HipDurableEvent>(OutboxPartition, auditEvent.EventId, auditEvent)],
            cancellationToken);
    }
}
