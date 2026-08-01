using System.Text.Json;
using FluentValidation;
using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Ai;

/// <summary>Immutable, privacy-safe AI suggestion with its normal HIP simulation evidence.</summary>
public sealed record AiRuleDraft(
    string DraftId,
    TrustRule ProposedRule,
    IReadOnlyCollection<string> EvidenceSummary,
    string ExpectedBenefit,
    IReadOnlyCollection<string> Risks,
    int Confidence,
    string ProviderName,
    bool IsPlaceholder,
    string SimulationId,
    bool SimulationPassed,
    string FixtureSetId,
    int PassedTestCount,
    int FailedTestCount,
    string RollbackPlan,
    DateTimeOffset CreatedAtUtc,
    long Version);

public interface IAiRuleDraftRepository
{
    Task<bool> TryCreateAsync(AiRuleDraft draft, CancellationToken cancellationToken);
    Task<AiRuleDraft?> GetAsync(string draftId, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AiRuleDraft>> ListAsync(CancellationToken cancellationToken);
}

public static class AiRuleDraftContract
{
    private static readonly string[] PrivateTerms =
    [
        "password", "token=", "bearer ", "authorization", "cookie", "private chat", "message body", "secret="
    ];

    public static void Validate(AiRuleDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(draft.ProposedRule);
        Safe(draft.DraftId, nameof(draft.DraftId), 48);
        Safe(draft.ProviderName, nameof(draft.ProviderName), 160);
        Safe(draft.ExpectedBenefit, nameof(draft.ExpectedBenefit), 500);
        Safe(draft.RollbackPlan, nameof(draft.RollbackPlan), 500);
        if (!draft.DraftId.StartsWith("ai-draft:", StringComparison.Ordinal) ||
            draft.DraftId is not { Length: 41 } || draft.Version != 1 || draft.CreatedAtUtc == default ||
            draft.Confidence is < 0 or > 100 ||
            draft.EvidenceSummary is null or { Count: < 1 or > 16 } ||
            draft.Risks is null or { Count: < 1 or > 8 } ||
            draft.PassedTestCount < 0 || draft.FailedTestCount < 0 ||
            draft.PassedTestCount + draft.FailedTestCount < 1 ||
            draft.SimulationPassed != (draft.FailedTestCount == 0) ||
            !draft.SimulationId.StartsWith("simulation:", StringComparison.Ordinal) ||
            !draft.FixtureSetId.StartsWith("fixtures:", StringComparison.Ordinal) ||
            draft.ProposedRule.CreatorType is not HipRuleCreatorType.AiSuggested ||
            !AiRuleIdentity.IsAiActor(draft.ProposedRule.CreatedBy) ||
            draft.ProposedRule.Enabled || draft.ProposedRule.Mode is not RuleMode.Disabled ||
            !draft.ProposedRule.RequiresApproval || !draft.ProposedRule.SimulationRequired ||
            draft.ProposedRule.ApprovalStatus is not ApprovalStatus.Pending)
        {
            throw new ArgumentException("AI rule draft metadata or safety state is inconsistent.", nameof(draft));
        }

        var ruleValidation = new TrustRuleValidator().Validate(draft.ProposedRule);
        if (!ruleValidation.IsValid ||
            !draft.ProposedRule.RuleId.StartsWith("ai-suggested-", StringComparison.Ordinal) ||
            draft.ProposedRule.Conditions.Count is < 1 or > 32 ||
            draft.ProposedRule.Actions.Count is < 1 or > 16 ||
            draft.ProposedRule.Conditions.Any(condition =>
                condition.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False or JsonValueKind.String or JsonValueKind.Number) ||
                condition.Operator is not (RuleOperator.Equals or RuleOperator.GreaterThan or RuleOperator.GreaterThanOrEqual or RuleOperator.LessThan or RuleOperator.LessThanOrEqual)) ||
            draft.ProposedRule.Actions.Any(action => action.Type is not (
                RuleActionType.AddReason or RuleActionType.MarkForSimulation or RuleActionType.SetRiskLevel or
                RuleActionType.RouteToSafetyPage or RuleActionType.RequireReview)))
        {
            throw new ArgumentException("AI rule draft fields, operators, or actions are not allow-listed.", nameof(draft));
        }

        foreach (var text in draft.EvidenceSummary.Concat(draft.Risks))
            Safe(text, nameof(draft), 500);
    }

    internal static string Safe(string value, string parameterName, int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > maximumLength || normalized.Any(char.IsControl) ||
            PrivateTerms.Any(term => normalized.Contains(term, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException("AI rule evidence must be bounded and privacy-safe.", parameterName);
        }
        return normalized;
    }
}

public sealed class AiRuleDraftService(
    IHipAiRiskAnalyzer analyzer,
    IValidator<TrustRule> validator,
    IRuleSimulationService simulationService,
    IRuleSimulationResultRepository simulations,
    IAiRuleDraftRepository drafts,
    RuleApprovalWorkflowService approvals,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<AiRuleDraft> CreateAsync(HipAiRuleSuggestionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Analysis);
        SafeOptional(request.Domain, nameof(request.Domain), 253);
        SafeOptional(request.Url, nameof(request.Url), 2_048);
        SafeOptional(request.Platform, nameof(request.Platform), 80);
        AiRuleDraftContract.Safe(request.Analysis.RecommendedAction, nameof(request), 160);
        if (request.Analysis.Reasons is null || request.Analysis.DetectedPatterns is null)
            throw new ArgumentException("AI analysis evidence collections are required.", nameof(request));
        foreach (var reason in request.Analysis.Reasons) AiRuleDraftContract.Safe(reason, nameof(request), 500);
        foreach (var pattern in request.Analysis.DetectedPatterns) AiRuleDraftContract.Safe(pattern, nameof(request), 100);

        var suggestion = await analyzer.SuggestRuleAsync(request, cancellationToken);
        var proposed = suggestion.ProposedRule with
        {
            Enabled = false,
            Mode = RuleMode.Disabled,
            RequiresApproval = true,
            SimulationRequired = true,
            CreatedBy = AiRuleIdentity.ProviderActor(suggestion.ProviderName),
            ApprovalStatus = ApprovalStatus.Pending,
            Version = 1,
            CreatorType = HipRuleCreatorType.AiSuggested,
            Conditions = Array.AsReadOnly(suggestion.ProposedRule.Conditions.ToArray()),
            Actions = Array.AsReadOnly(suggestion.ProposedRule.Actions.ToArray())
        };
        await validator.ValidateAndThrowAsync(proposed, cancellationToken);

        var simulation = simulationService.Simulate(
            proposed with { Enabled = true, Mode = RuleMode.Active },
            BuildFixtures(proposed));
        await simulations.SaveAsync(simulation.SimulationId, simulation, cancellationToken);

        var evidence = request.Analysis.Reasons
            .Concat(request.Analysis.DetectedPatterns.Select(pattern => $"Pattern: {pattern}"))
            .DefaultIfEmpty("No strong pattern evidence was supplied; human review is required.")
            .Take(16)
            .ToArray();
        var draft = new AiRuleDraft(
            $"ai-draft:{Guid.NewGuid():N}",
            proposed,
            Array.AsReadOnly(evidence),
            $"Evaluate the proposed {request.Analysis.RecommendedAction} response using structured HIP evidence.",
            Array.AsReadOnly(new[]
            {
                "False positives could inconvenience or misdirect users.",
                "AI output may be incomplete or incorrect and is not authoritative."
            }),
            request.Analysis.Confidence,
            suggestion.ProviderName,
            suggestion.IsPlaceholder,
            simulation.SimulationId,
            simulation.Passed,
            simulation.FixtureSetId,
            simulation.PassedCount,
            simulation.FailedCount,
            "Restore the prior deployed rule version or the known disabled state.",
            timeProvider.GetUtcNow(),
            Version: 1);
        AiRuleDraftContract.Validate(draft);
        if (!await drafts.TryCreateAsync(draft, cancellationToken))
            throw new InvalidOperationException("The immutable AI rule draft already exists.");
        return draft;
    }

    public Task<AiRuleDraft?> GetAsync(string draftId, CancellationToken cancellationToken) =>
        drafts.GetAsync(draftId, cancellationToken);

    public Task<IReadOnlyCollection<AiRuleDraft>> ListAsync(CancellationToken cancellationToken) =>
        drafts.ListAsync(cancellationToken);

    public async Task<RuleApprovalWorkflowState> SubmitForApprovalAsync(
        string draftId,
        string actorId,
        CancellationToken cancellationToken)
    {
        AiRuleIdentity.RejectAiActor(actorId);
        var draft = await drafts.GetAsync(draftId, cancellationToken) ??
                    throw new InvalidOperationException("AI rule draft was not found.");
        AiRuleDraftContract.Validate(draft);
        if (!draft.SimulationPassed)
            throw new InvalidOperationException("A failed AI draft simulation cannot enter approval.");
        var simulatedCandidate = draft.ProposedRule with
        {
            Enabled = true,
            Mode = RuleMode.Active
        };
        return await approvals.RequestAsync(simulatedCandidate, draft.SimulationId, actorId, cancellationToken);
    }

    private static IReadOnlyCollection<RuleSimulationTestCase> BuildFixtures(TrustRule rule)
    {
        var matching = new Dictionary<string, object?>(StringComparer.Ordinal);
        var nonMatching = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var condition in rule.Conditions)
        {
            var expected = Value(condition.Value);
            matching[condition.Field] = MatchingValue(condition.Operator, expected);
            nonMatching[condition.Field] = NonMatchingValue(condition.Operator, expected);
        }

        var risk = rule.Actions
            .FirstOrDefault(action => action.Type is RuleActionType.SetRiskLevel)?.Value.GetString();
        RiskStatus? expectedRisk = Enum.TryParse<RiskStatus>(risk, ignoreCase: true, out var parsedRisk)
            ? parsedRisk
            : null;
        var routes = rule.Actions.Any(action => action.Type is RuleActionType.RouteToSafetyPage);
        return
        [
            new("AI draft synthetic match", new FactSet(matching), true, expectedRisk, routes ? true : null),
            new("AI draft synthetic non-match", new FactSet(nonMatching), false, null, null)
        ];
    }

    private static object? Value(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number when value.TryGetInt32(out var integer) => integer,
        _ => throw new ArgumentException("AI rule conditions require scalar typed values.")
    };

    private static object? MatchingValue(RuleOperator op, object? expected) => op switch
    {
        RuleOperator.Equals => expected,
        RuleOperator.GreaterThan when expected is int value => value + 1,
        RuleOperator.GreaterThanOrEqual => expected,
        RuleOperator.LessThan when expected is int value => value - 1,
        RuleOperator.LessThanOrEqual => expected,
        _ => throw new ArgumentException("AI rule condition operator cannot be simulated safely.")
    };

    private static object? NonMatchingValue(RuleOperator op, object? expected) => expected switch
    {
        bool value => !value,
        string => "known-safe-non-match.example",
        int value when op is RuleOperator.GreaterThan or RuleOperator.GreaterThanOrEqual => value - 1,
        int value when op is RuleOperator.LessThan or RuleOperator.LessThanOrEqual => value + 1,
        int value => value + 1,
        _ => throw new ArgumentException("AI rule condition value cannot be simulated safely.")
    };

    private static void SafeOptional(string? value, string parameterName, int maximumLength)
    {
        if (value is not null) AiRuleDraftContract.Safe(value, parameterName, maximumLength);
    }
}

public sealed class InMemoryAiRuleDraftRepository : IAiRuleDraftRepository
{
    private readonly Dictionary<string, AiRuleDraft> drafts = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<bool> TryCreateAsync(AiRuleDraft draft, CancellationToken cancellationToken)
    {
        AiRuleDraftContract.Validate(draft);
        await gate.WaitAsync(cancellationToken);
        try { return drafts.TryAdd(draft.DraftId, draft); }
        finally { gate.Release(); }
    }

    public async Task<AiRuleDraft?> GetAsync(string draftId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(draftId) || draftId.Length > 48) return null;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var draft = drafts.GetValueOrDefault(draftId);
            if (draft is not null) AiRuleDraftContract.Validate(draft);
            return draft;
        }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyCollection<AiRuleDraft>> ListAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return drafts.Values.OrderByDescending(draft => draft.CreatedAtUtc).ToArray(); }
        finally { gate.Release(); }
    }
}
