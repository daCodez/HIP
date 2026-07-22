using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HIP.Application.Scalability;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public enum RuleDeploymentStatus { Watch, Active, Disabled }

/// <summary>Authoritative deployed snapshot and its single controlled rollback target.</summary>
public sealed record RuleDeploymentState(
    string DeploymentId,
    string RuleId,
    TrustRule? ActiveRule,
    TrustRule? RollbackRule,
    bool UseDisabledRollback,
    bool RollbackAvailable,
    RuleDeploymentStatus Status,
    string WorkflowId,
    string LastTransitionId,
    string LastTransitionType,
    string LastActorId,
    string LastReason,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    long Version);

public interface IRuleDeploymentRepository
{
    Task<RuleDeploymentState?> GetAsync(string ruleId, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<RuleDeploymentState>> ListAsync(CancellationToken cancellationToken);
    Task<bool> TryCreateAsync(RuleDeploymentState state, HipDurableEvent auditEvent, CancellationToken cancellationToken);
    Task<bool> TryUpdateAsync(RuleDeploymentState state, long expectedVersion, HipDurableEvent auditEvent, CancellationToken cancellationToken);
}

public static class RuleDeploymentContract
{
    public static void Validate(RuleDeploymentState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        Safe(state.RuleId, nameof(state.RuleId), 160);
        Safe(state.WorkflowId, nameof(state.WorkflowId), 160);
        Safe(state.DeploymentId, nameof(state.DeploymentId), 64);
        Safe(state.LastTransitionId, nameof(state.LastTransitionId), 64);
        Safe(state.LastTransitionType, nameof(state.LastTransitionType), 64);
        Safe(state.LastActorId, nameof(state.LastActorId), 160);
        Safe(state.LastReason, nameof(state.LastReason), 500);
        if (!string.Equals(state.DeploymentId, DeploymentId(state.RuleId), StringComparison.Ordinal) ||
            state.LastTransitionId is not { Length: 48 } ||
            !state.LastTransitionId.StartsWith("rule-transition:", StringComparison.Ordinal) ||
            !state.LastTransitionId.AsSpan("rule-transition:".Length).ToString().All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            !RuleApprovalWorkflowContract.IsCanonicalWorkflowId(state.WorkflowId) ||
            state.Version <= 0 || state.CreatedAtUtc == default || state.UpdatedAtUtc < state.CreatedAtUtc ||
            state.ActiveRule is null != (state.Status is RuleDeploymentStatus.Disabled) ||
            state.ActiveRule is not null && !string.Equals(state.ActiveRule.RuleId, state.RuleId, StringComparison.Ordinal) ||
            state.ActiveRule is not null && state.Status != Status(state.ActiveRule.Mode) ||
            state.RollbackAvailable != ((state.RollbackRule is null) != !state.UseDisabledRollback) ||
            !state.RollbackAvailable && (state.RollbackRule is not null || state.UseDisabledRollback) ||
            state.RollbackRule is not null && !string.Equals(state.RollbackRule.RuleId, state.RuleId, StringComparison.Ordinal) ||
            state.RollbackRule is not null && state.ActiveRule is not null && state.RollbackRule.Version == state.ActiveRule.Version)
        {
            throw new ArgumentException("Rule deployment state is inconsistent.", nameof(state));
        }
    }

    public static string DeploymentId(string ruleId)
    {
        var normalized = Safe(ruleId, nameof(ruleId), 160);
        return $"rule-deployment:{Digest(normalized)[..32]}";
    }

    internal static string Safe(string value, string parameterName, int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > maximumLength || normalized.Any(char.IsControl))
            throw new ArgumentException("Rule deployment text must be bounded plain text.", parameterName);
        return normalized;
    }

    internal static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static RuleDeploymentStatus Status(RuleMode mode) => mode switch
    {
        RuleMode.Watch => RuleDeploymentStatus.Watch,
        RuleMode.Active => RuleDeploymentStatus.Active,
        RuleMode.Disabled => RuleDeploymentStatus.Disabled,
        _ => throw new ArgumentOutOfRangeException(nameof(mode))
    };
}

/// <summary>Performs exact-workflow activation and one-action rollback using optimistic concurrency.</summary>
public sealed class RuleDeploymentService(
    IRuleDeploymentRepository repository,
    IRuleRepository rules,
    RuleApprovalWorkflowService approvals,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<RuleDeploymentState> ActivateAsync(
        string workflowId,
        string actorId,
        string reason,
        CancellationToken cancellationToken)
    {
        var actor = RuleDeploymentContract.Safe(actorId, nameof(actorId), 160);
        AiRuleIdentity.RejectAiActor(actor);
        var normalizedReason = RuleDeploymentContract.Safe(reason, nameof(reason), 500);
        var workflow = await approvals.GetAsync(workflowId, cancellationToken) ??
                       throw new InvalidOperationException("Rule approval workflow was not found.");
        if (!RuleApprovalWorkflowService.CanActivate(workflow))
            throw new InvalidOperationException("The exact approval workflow cannot activate this rule version.");

        var candidate = workflow.RuleSnapshot;
        var currentDefinition = await rules.GetByIdAsync(workflow.RuleId, cancellationToken);
        if (currentDefinition is not null &&
            (currentDefinition.Version != workflow.RuleVersion ||
             !string.Equals(
                 JsonSerializer.Serialize(currentDefinition),
                 JsonSerializer.Serialize(candidate),
                 StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("The approval workflow is stale for the current rule version.");
        }

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var current = await repository.GetAsync(workflow.RuleId, cancellationToken);
            if (current?.WorkflowId == workflow.WorkflowId)
                throw new InvalidOperationException("This approval workflow was already deployed.");
            if (current?.ActiveRule?.Version == workflow.RuleVersion)
                throw new InvalidOperationException("This exact rule version is already deployed.");

            var now = timeProvider.GetUtcNow();
            var activeMode = workflow.ImpactLevel is HipRuleImpactLevel.High
                ? RuleMode.Watch
                : candidate.Mode is RuleMode.Disabled ? RuleMode.Active : candidate.Mode;
            var active = candidate with
            {
                Enabled = true,
                Mode = activeMode,
                RequiresApproval = workflow.RequiredApprovalCount > 0,
                ApprovalStatus = workflow.RequiredApprovalCount > 0 ? ApprovalStatus.Approved : ApprovalStatus.NotRequired
            };
            var state = new RuleDeploymentState(
                RuleDeploymentContract.DeploymentId(workflow.RuleId),
                workflow.RuleId,
                active,
                current?.ActiveRule,
                UseDisabledRollback: current?.ActiveRule is null,
                RollbackAvailable: true,
                activeMode is RuleMode.Watch ? RuleDeploymentStatus.Watch : RuleDeploymentStatus.Active,
                workflow.WorkflowId,
                $"rule-transition:{Guid.NewGuid():N}",
                "Activated",
                actor,
                normalizedReason,
                current?.CreatedAtUtc ?? now,
                now,
                Version: (current?.Version ?? 0) + 1);
            RuleDeploymentContract.Validate(state);
            var auditEvent = Event(state, "RuleVersionActivated", actor, normalizedReason, current?.ActiveRule?.Version);
            var saved = current is null
                ? await repository.TryCreateAsync(state, auditEvent, cancellationToken)
                : await repository.TryUpdateAsync(state, current.Version, auditEvent, cancellationToken);
            if (saved) return state;
        }
        throw new InvalidOperationException("Concurrent deployments prevented a safe activation.");
    }

    public async Task<RuleDeploymentState> RollbackAsync(
        string ruleId,
        long expectedVersion,
        string actorId,
        string reason,
        CancellationToken cancellationToken)
    {
        var normalizedRuleId = RuleDeploymentContract.Safe(ruleId, nameof(ruleId), 160);
        var actor = RuleDeploymentContract.Safe(actorId, nameof(actorId), 160);
        AiRuleIdentity.RejectAiActor(actor);
        var normalizedReason = RuleDeploymentContract.Safe(reason, nameof(reason), 500);
        var current = await repository.GetAsync(normalizedRuleId, cancellationToken) ??
                      throw new InvalidOperationException("Rule deployment was not found.");
        if (current.Version != expectedVersion)
            throw new InvalidOperationException("The rollback request is stale.");
        if (!current.RollbackAvailable)
            throw new InvalidOperationException("A rollback target is not available.");

        var now = timeProvider.GetUtcNow();
        var target = current.RollbackRule;
        var updated = current with
        {
            ActiveRule = target,
            RollbackRule = null,
            UseDisabledRollback = false,
            RollbackAvailable = false,
            Status = target is null
                ? RuleDeploymentStatus.Disabled
                : target.Mode is RuleMode.Watch ? RuleDeploymentStatus.Watch : RuleDeploymentStatus.Active,
            LastTransitionId = $"rule-transition:{Guid.NewGuid():N}",
            LastTransitionType = target is null ? "RolledBackToDisabled" : "RolledBackToVersion",
            LastActorId = actor,
            LastReason = normalizedReason,
            UpdatedAtUtc = now,
            Version = current.Version + 1
        };
        RuleDeploymentContract.Validate(updated);
        if (!await repository.TryUpdateAsync(
                updated,
                expectedVersion,
                Event(updated, "RuleVersionRolledBack", actor, normalizedReason, current.ActiveRule?.Version),
                cancellationToken))
        {
            throw new InvalidOperationException("The rollback request lost a concurrency race.");
        }
        return updated;
    }

    public async Task<RuleDeploymentState> PromoteAsync(
        string ruleId,
        long expectedVersion,
        string actorId,
        string reason,
        CancellationToken cancellationToken)
    {
        var normalizedRuleId = RuleDeploymentContract.Safe(ruleId, nameof(ruleId), 160);
        var actor = RuleDeploymentContract.Safe(actorId, nameof(actorId), 160);
        AiRuleIdentity.RejectAiActor(actor);
        var normalizedReason = RuleDeploymentContract.Safe(reason, nameof(reason), 500);
        var current = await repository.GetAsync(normalizedRuleId, cancellationToken) ??
                      throw new InvalidOperationException("Rule deployment was not found.");
        if (current.Version != expectedVersion)
            throw new InvalidOperationException("The promotion request is stale.");
        if (current.Status is not RuleDeploymentStatus.Watch || current.ActiveRule is null)
            throw new InvalidOperationException("Only a watch-mode deployment can be promoted.");

        var updated = current with
        {
            ActiveRule = current.ActiveRule with { Mode = RuleMode.Active },
            Status = RuleDeploymentStatus.Active,
            LastTransitionId = $"rule-transition:{Guid.NewGuid():N}",
            LastTransitionType = "PromotedFromWatch",
            LastActorId = actor,
            LastReason = normalizedReason,
            UpdatedAtUtc = timeProvider.GetUtcNow(),
            Version = current.Version + 1
        };
        RuleDeploymentContract.Validate(updated);
        if (!await repository.TryUpdateAsync(
                updated,
                expectedVersion,
                Event(updated, "RuleVersionPromoted", actor, normalizedReason, current.ActiveRule.Version),
                cancellationToken))
        {
            throw new InvalidOperationException("The promotion request lost a concurrency race.");
        }
        return updated;
    }

    public Task<RuleDeploymentState?> GetAsync(string ruleId, CancellationToken cancellationToken) =>
        repository.GetAsync(ruleId, cancellationToken);

    private static HipDurableEvent Event(
        RuleDeploymentState state,
        string eventType,
        string actor,
        string reason,
        int? replacedVersion) =>
        new(
            $"evt:{Guid.NewGuid():N}",
            eventType,
            "RuleDeployment",
            state.DeploymentId,
            state.UpdatedAtUtc,
            JsonSerializer.Serialize(new
            {
                state.RuleId,
                ActiveVersion = state.ActiveRule?.Version,
                ReplacedVersion = replacedVersion,
                state.Status,
                ActorDigest = RuleDeploymentContract.Digest(actor),
                ReasonDigest = RuleDeploymentContract.Digest(reason),
                state.LastTransitionId
            }),
            HipDurableEventPrivacyLevel.PublicSafe);
}

public sealed class InMemoryRuleDeploymentRepository(IOutboxEventRepository outbox) : IRuleDeploymentRepository
{
    private readonly Dictionary<string, RuleDeploymentState> states = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<RuleDeploymentState?> GetAsync(string ruleId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ruleId) || ruleId.Length > 160) return null;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var state = states.GetValueOrDefault(ruleId);
            if (state is not null) RuleDeploymentContract.Validate(state);
            return state;
        }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyCollection<RuleDeploymentState>> ListAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var state in states.Values) RuleDeploymentContract.Validate(state);
            return states.Values.OrderBy(state => state.RuleId, StringComparer.Ordinal).ToArray();
        }
        finally { gate.Release(); }
    }

    public Task<bool> TryCreateAsync(RuleDeploymentState state, HipDurableEvent auditEvent, CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion: 0, auditEvent, cancellationToken);

    public Task<bool> TryUpdateAsync(RuleDeploymentState state, long expectedVersion, HipDurableEvent auditEvent, CancellationToken cancellationToken) =>
        SaveAsync(state, expectedVersion, auditEvent, cancellationToken);

    private async Task<bool> SaveAsync(
        RuleDeploymentState state,
        long expectedVersion,
        HipDurableEvent auditEvent,
        CancellationToken cancellationToken)
    {
        RuleDeploymentContract.Validate(state);
        ArgumentNullException.ThrowIfNull(auditEvent);
        if (state.Version != expectedVersion + 1 || auditEvent.AggregateId != state.DeploymentId)
            throw new ArgumentException("Rule deployment transition metadata is inconsistent.", nameof(state));
        await gate.WaitAsync(cancellationToken);
        try
        {
            var exists = states.TryGetValue(state.RuleId, out var current);
            if (expectedVersion == 0 ? exists : !exists || current!.Version != expectedVersion) return false;
            await outbox.SaveAsync(auditEvent, cancellationToken);
            states[state.RuleId] = state;
            return true;
        }
        finally { gate.Release(); }
    }
}
