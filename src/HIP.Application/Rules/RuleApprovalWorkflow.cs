using System.Security.Cryptography;
using System.Text;
using HIP.Application.Scalability;
using HIP.Application.Simulation;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public enum RuleApprovalWorkflowStatus { Pending, ApprovalSatisfied, ReadyForActivation }

public sealed record RuleVersionApproval(
    string ApprovalId,
    string ApproverId,
    DateTimeOffset ApprovedAtUtc);

/// <summary>Immutable approval state bound to one rule version and one successful simulation.</summary>
public sealed record RuleApprovalWorkflowState(
    string WorkflowId,
    string RuleId,
    int RuleVersion,
    string CreatorId,
    string SimulationId,
    TrustRule RuleSnapshot,
    HipRuleImpactLevel ImpactLevel,
    int RequiredApprovalCount,
    bool ManualDeploymentRequired,
    bool RollbackTestRequired,
    bool RollbackTestCompleted,
    bool ManualDeploymentAuthorized,
    RuleApprovalWorkflowStatus Status,
    IReadOnlyCollection<RuleVersionApproval> Approvals,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    long Version);

public interface IRuleApprovalWorkflowRepository
{
    Task<bool> TryCreateAsync(RuleApprovalWorkflowState state, HipDurableEvent auditEvent, CancellationToken cancellationToken);
    Task<RuleApprovalWorkflowState?> GetAsync(string workflowId, CancellationToken cancellationToken);
    Task<bool> TryUpdateAsync(RuleApprovalWorkflowState state, long expectedVersion, HipDurableEvent auditEvent, CancellationToken cancellationToken);
}

public static class RuleApprovalWorkflowContract
{
    private const string WorkflowPrefix = "rule-approval:";

    public static void Validate(RuleApprovalWorkflowState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(state.RuleSnapshot);
        if (!IsCanonicalWorkflowId(state.WorkflowId) ||
            state.RuleVersion <= 0 || state.Version <= 0 ||
            state.RequestedAtUtc == default || state.UpdatedAtUtc < state.RequestedAtUtc ||
            state.RequiredApprovalCount is < 0 or > 2 ||
            state.Approvals is null || state.Approvals.Count > state.RequiredApprovalCount ||
            state.Approvals.Select(value => value.ApproverId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != state.Approvals.Count ||
            state.Approvals.Any(value => string.Equals(value.ApproverId, state.CreatorId, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("Rule approval workflow metadata is inconsistent.", nameof(state));
        }

        Required(state.RuleId, nameof(state.RuleId));
        Required(state.CreatorId, nameof(state.CreatorId));
        Required(state.SimulationId, nameof(state.SimulationId));
        if (!string.Equals(state.RuleSnapshot.RuleId, state.RuleId, StringComparison.Ordinal) ||
            state.RuleSnapshot.Version != state.RuleVersion ||
            !string.Equals(state.RuleSnapshot.CreatedBy, state.CreatorId, StringComparison.Ordinal) ||
            state.RuleSnapshot.Conditions is null || state.RuleSnapshot.Actions is null)
        {
            throw new ArgumentException("The approval workflow rule snapshot is inconsistent.", nameof(state));
        }
        foreach (var approval in state.Approvals)
        {
            Required(approval.ApprovalId, nameof(approval.ApprovalId));
            Required(approval.ApproverId, nameof(approval.ApproverId));
            if (approval.ApprovedAtUtc < state.RequestedAtUtc || approval.ApprovedAtUtc > state.UpdatedAtUtc)
            {
                throw new ArgumentException("Rule approval timestamps are inconsistent.", nameof(state));
            }
        }

        var approvalsSatisfied = state.Approvals.Count >= state.RequiredApprovalCount;
        var expectedApprovalCount = state.RuleSnapshot.CreatorType is HipRuleCreatorType.AiSuggested
            ? Math.Max(1, ImpactApprovalCount(state.ImpactLevel))
            : ImpactApprovalCount(state.ImpactLevel);
        var snapshotImpact = Impact(state.RuleSnapshot.Severity);
        var expectedStatus = approvalsSatisfied
            ? state.ManualDeploymentRequired && !state.ManualDeploymentAuthorized
                ? RuleApprovalWorkflowStatus.ApprovalSatisfied
                : RuleApprovalWorkflowStatus.ReadyForActivation
            : RuleApprovalWorkflowStatus.Pending;
        if (state.Status != expectedStatus ||
            state.RequiredApprovalCount != expectedApprovalCount ||
            state.ImpactLevel != snapshotImpact ||
            state.ManualDeploymentRequired != (state.ImpactLevel is HipRuleImpactLevel.Critical) ||
            state.RollbackTestRequired != (state.ImpactLevel is HipRuleImpactLevel.Critical) ||
            (state.RollbackTestCompleted && !state.RollbackTestRequired) ||
            (state.ManualDeploymentAuthorized &&
             (!state.ManualDeploymentRequired || !state.RollbackTestCompleted || !approvalsSatisfied)) ||
            (state.ImpactLevel is HipRuleImpactLevel.Critical &&
             (!state.ManualDeploymentRequired || !state.RollbackTestRequired || state.RequiredApprovalCount != 2)))
        {
            throw new ArgumentException("Rule approval workflow status or policy is inconsistent.", nameof(state));
        }
    }

    public static bool IsCanonicalWorkflowId(string? value) =>
        value is { Length: 46 } &&
        value.StartsWith(WorkflowPrefix, StringComparison.Ordinal) &&
        value.AsSpan(WorkflowPrefix.Length).ToString().All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static string Required(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > 160 || normalized.Any(char.IsControl))
        {
            throw new ArgumentException("Rule approval identifiers must be bounded plain text.", parameterName);
        }
        return normalized;
    }

    private static HipRuleImpactLevel Impact(RuleSeverity severity) => severity switch
    {
        RuleSeverity.Low => HipRuleImpactLevel.Low,
        RuleSeverity.Medium or RuleSeverity.Caution => HipRuleImpactLevel.Medium,
        RuleSeverity.High or RuleSeverity.HighRisk => HipRuleImpactLevel.High,
        RuleSeverity.Critical or RuleSeverity.Dangerous => HipRuleImpactLevel.Critical,
        _ => throw new ArgumentOutOfRangeException(nameof(severity))
    };

    internal static int ImpactApprovalCount(HipRuleImpactLevel impact) => impact switch
    {
        HipRuleImpactLevel.Low => 0,
        HipRuleImpactLevel.Medium => 1,
        HipRuleImpactLevel.High or HipRuleImpactLevel.Critical => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(impact))
    };
}

/// <summary>Impact-based, simulation-bound, creator-independent approval workflow.</summary>
public sealed class RuleApprovalWorkflowService(
    IRuleApprovalWorkflowRepository repository,
    IRuleSimulationResultRepository simulations,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<RuleApprovalWorkflowState> RequestAsync(
        TrustRule rule,
        string simulationId,
        CancellationToken cancellationToken) =>
        await RequestAsync(rule, simulationId, rule.CreatedBy, cancellationToken);

    public async Task<RuleApprovalWorkflowState> RequestAsync(
        TrustRule rule,
        string simulationId,
        string requesterActorId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var requester = Required(requesterActorId, nameof(requesterActorId));
        if (rule.CreatorType is HipRuleCreatorType.AiSuggested) AiRuleIdentity.RejectAiActor(requester);
        var simulation = await simulations.GetAsync(simulationId, cancellationToken) ??
                         throw new InvalidOperationException("The exact simulation result was not found.");
        if (!simulation.Passed ||
            simulation.RuleId != rule.RuleId ||
            simulation.RuleVersion != rule.Version ||
            string.IsNullOrWhiteSpace(simulation.RuleDefinitionHash) ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(simulation.RuleDefinitionHash),
                Encoding.UTF8.GetBytes(RuleDefinitionFingerprint.Compute(rule))))
        {
            throw new InvalidOperationException("Approval requires a passing simulation for the exact rule version.");
        }

        var impact = Impact(rule.Severity);
        var required = rule.CreatorType is HipRuleCreatorType.AiSuggested
            ? Math.Max(1, RuleApprovalWorkflowContract.ImpactApprovalCount(impact))
            : RuleApprovalWorkflowContract.ImpactApprovalCount(impact);
        var now = timeProvider.GetUtcNow();
        var workflow = new RuleApprovalWorkflowState(
            WorkflowId(rule.RuleId, rule.Version, simulation.SimulationId),
            Required(rule.RuleId, nameof(rule.RuleId)),
            rule.Version,
            Required(rule.CreatedBy, nameof(rule.CreatedBy)),
            simulation.SimulationId,
            rule with
            {
                Conditions = Array.AsReadOnly(rule.Conditions.ToArray()),
                Actions = Array.AsReadOnly(rule.Actions.ToArray())
            },
            impact,
            required,
            ManualDeploymentRequired: impact is HipRuleImpactLevel.Critical,
            RollbackTestRequired: impact is HipRuleImpactLevel.Critical,
            RollbackTestCompleted: false,
            ManualDeploymentAuthorized: false,
            required == 0 ? RuleApprovalWorkflowStatus.ReadyForActivation : RuleApprovalWorkflowStatus.Pending,
            [],
            now,
            now,
            Version: 1);
        var auditEvent = Event(workflow, "RuleApprovalRequested", requester, now);
        if (!await repository.TryCreateAsync(workflow, auditEvent, cancellationToken))
        {
            throw new InvalidOperationException("An approval workflow already exists for this exact rule version and simulation.");
        }
        return workflow;
    }

    public async Task<RuleApprovalWorkflowState> ApproveAsync(
        string workflowId,
        string actorId,
        CancellationToken cancellationToken)
    {
        var actor = Required(actorId, nameof(actorId));
        AiRuleIdentity.RejectAiActor(actor);
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var current = await repository.GetAsync(workflowId, cancellationToken) ??
                          throw new InvalidOperationException("Rule approval workflow was not found.");
            if (string.Equals(current.CreatorId, actor, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("A rule creator cannot approve the same rule version.");
            }
            if (current.Approvals.Any(value => string.Equals(value.ApproverId, actor, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("This actor already approved the rule version.");
            }
            if (current.Approvals.Count >= current.RequiredApprovalCount)
            {
                throw new InvalidOperationException("The required approval count is already satisfied.");
            }

            var now = timeProvider.GetUtcNow();
            var approvals = current.Approvals.Append(new RuleVersionApproval(
                $"approval:{Guid.NewGuid():N}", actor, now)).ToArray();
            var status = approvals.Length >= current.RequiredApprovalCount
                ? current.ManualDeploymentRequired
                    ? RuleApprovalWorkflowStatus.ApprovalSatisfied
                    : RuleApprovalWorkflowStatus.ReadyForActivation
                : RuleApprovalWorkflowStatus.Pending;
            var updated = current with
            {
                Approvals = Array.AsReadOnly(approvals),
                Status = status,
                UpdatedAtUtc = now,
                Version = current.Version + 1
            };
            if (await repository.TryUpdateAsync(
                    updated,
                    current.Version,
                    Event(updated, "RuleVersionApproved", actor, now),
                    cancellationToken))
            {
                return updated;
            }
        }
        throw new InvalidOperationException("Concurrent approval changes prevented a safe update.");
    }

    public async Task<RuleApprovalWorkflowState> CompleteRollbackTestAsync(
        string workflowId,
        string actorId,
        string reason,
        CancellationToken cancellationToken) =>
        await TransitionAsync(
            workflowId,
            actorId,
            reason,
            "RuleRollbackTestCompleted",
            current =>
            {
                if (!current.RollbackTestRequired)
                    throw new InvalidOperationException("This workflow does not require a rollback test.");
                if (current.Approvals.Count < current.RequiredApprovalCount)
                    throw new InvalidOperationException("Required approvals must be complete before the rollback test.");
                if (current.RollbackTestCompleted)
                    throw new InvalidOperationException("The rollback test is already complete.");
                return current with { RollbackTestCompleted = true };
            },
            cancellationToken);

    public async Task<RuleApprovalWorkflowState> AuthorizeManualDeploymentAsync(
        string workflowId,
        string actorId,
        string reason,
        CancellationToken cancellationToken) =>
        await TransitionAsync(
            workflowId,
            actorId,
            reason,
            "RuleManualDeploymentAuthorized",
            current =>
            {
                if (!current.ManualDeploymentRequired)
                    throw new InvalidOperationException("This workflow does not require manual deployment authorization.");
                if (!current.RollbackTestCompleted)
                    throw new InvalidOperationException("The rollback test must be complete before manual deployment authorization.");
                if (current.ManualDeploymentAuthorized)
                    throw new InvalidOperationException("Manual deployment is already authorized.");
                return current with
                {
                    ManualDeploymentAuthorized = true,
                    Status = RuleApprovalWorkflowStatus.ReadyForActivation
                };
            },
            cancellationToken);

    public async Task<RuleApprovalWorkflowState?> GetAsync(string workflowId, CancellationToken cancellationToken)
    {
        if (!RuleApprovalWorkflowContract.IsCanonicalWorkflowId(workflowId)) return null;
        var state = await repository.GetAsync(workflowId, cancellationToken);
        if (state is not null) RuleApprovalWorkflowContract.Validate(state);
        return state;
    }

    public static bool CanActivate(RuleApprovalWorkflowState state) =>
        state.Approvals.Count >= state.RequiredApprovalCount &&
        (!state.RollbackTestRequired || state.RollbackTestCompleted) &&
        (!state.ManualDeploymentRequired || state.ManualDeploymentAuthorized) &&
        state.Status is RuleApprovalWorkflowStatus.ReadyForActivation;

    private async Task<RuleApprovalWorkflowState> TransitionAsync(
        string workflowId,
        string actorId,
        string reason,
        string eventType,
        Func<RuleApprovalWorkflowState, RuleApprovalWorkflowState> transition,
        CancellationToken cancellationToken)
    {
        var actor = Required(actorId, nameof(actorId));
        AiRuleIdentity.RejectAiActor(actor);
        var normalizedReason = RequiredReason(reason);
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var current = await GetAsync(workflowId, cancellationToken) ??
                          throw new InvalidOperationException("Rule approval workflow was not found.");
            var now = timeProvider.GetUtcNow();
            var updated = transition(current) with
            {
                UpdatedAtUtc = now,
                Version = current.Version + 1
            };
            if (await repository.TryUpdateAsync(
                    updated,
                    current.Version,
                    Event(updated, eventType, actor, now, normalizedReason),
                    cancellationToken))
            {
                return updated;
            }
        }
        throw new InvalidOperationException("Concurrent approval changes prevented a safe update.");
    }

    private static HipRuleImpactLevel Impact(RuleSeverity severity) => severity switch
    {
        RuleSeverity.Low => HipRuleImpactLevel.Low,
        RuleSeverity.Medium or RuleSeverity.Caution => HipRuleImpactLevel.Medium,
        RuleSeverity.High or RuleSeverity.HighRisk => HipRuleImpactLevel.High,
        RuleSeverity.Critical or RuleSeverity.Dangerous => HipRuleImpactLevel.Critical,
        _ => throw new ArgumentOutOfRangeException(nameof(severity))
    };

    private static HipDurableEvent Event(
        RuleApprovalWorkflowState state,
        string type,
        string actor,
        DateTimeOffset at,
        string? reason = null) =>
        new(
            $"evt:{Guid.NewGuid():N}",
            type,
            "RuleApprovalWorkflow",
            state.WorkflowId,
            at,
            System.Text.Json.JsonSerializer.Serialize(new
            {
                state.WorkflowId,
                state.RuleId,
                state.RuleVersion,
                ActorDigest = Digest(actor),
                ReasonDigest = reason is null ? null : Digest(reason),
                state.Status
            }),
            HipDurableEventPrivacyLevel.PublicSafe);

    private static string WorkflowId(string ruleId, int ruleVersion, string simulationId)
    {
        var binding = $"{Required(ruleId, nameof(ruleId))}\n{ruleVersion}\n{Required(simulationId, nameof(simulationId))}";
        return $"rule-approval:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(binding))).ToLowerInvariant()[..32]}";
    }

    private static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string RequiredReason(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        var normalized = reason.Trim();
        if (normalized.Length > 500 || normalized.Any(char.IsControl))
            throw new ArgumentException("Rule transition reasons must be bounded plain text.", nameof(reason));
        return normalized;
    }

    private static string Required(string value, string parameterName) =>
        RuleApprovalWorkflowContract.Required(value, parameterName);
}

public sealed class InMemoryRuleApprovalWorkflowRepository(IOutboxEventRepository outbox) : IRuleApprovalWorkflowRepository
{
    private readonly Dictionary<string, RuleApprovalWorkflowState> states = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<bool> TryCreateAsync(RuleApprovalWorkflowState state, HipDurableEvent auditEvent, CancellationToken cancellationToken)
    {
        RuleApprovalWorkflowContract.Validate(state);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (states.ContainsKey(state.WorkflowId)) return false;
            await outbox.SaveAsync(auditEvent, cancellationToken);
            states.Add(state.WorkflowId, state);
            return true;
        }
        finally { gate.Release(); }
    }

    public async Task<RuleApprovalWorkflowState?> GetAsync(string workflowId, CancellationToken cancellationToken)
    {
        if (!RuleApprovalWorkflowContract.IsCanonicalWorkflowId(workflowId)) return null;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var state = states.GetValueOrDefault(workflowId);
            if (state is not null) RuleApprovalWorkflowContract.Validate(state);
            return state;
        }
        finally { gate.Release(); }
    }

    public async Task<bool> TryUpdateAsync(RuleApprovalWorkflowState state, long expectedVersion, HipDurableEvent auditEvent, CancellationToken cancellationToken)
    {
        RuleApprovalWorkflowContract.Validate(state);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!states.TryGetValue(state.WorkflowId, out var current) || current.Version != expectedVersion) return false;
            await outbox.SaveAsync(auditEvent, cancellationToken);
            states[state.WorkflowId] = state;
            return true;
        }
        finally { gate.Release(); }
    }
}
