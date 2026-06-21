using HIP.Domain.Rules;

namespace HIP.Application.Rules;

/// <summary>
/// Status: Updated
/// Changed: 2026-06-21 09:33 UTC
/// Developer: HIP Development Team
/// Assisted by: Codex
/// Description: Walks each rule condition and delegates operator logic to a focused evaluator so rule matching is easier to test.
/// </summary>
public sealed class RuleMatchingEngine : IRuleMatchingEngine
{
    private readonly IRuleConditionEvaluator conditionEvaluator;

    /// <summary>
    /// Creates a matching engine with the built-in HIP condition evaluator.
    /// </summary>
    public RuleMatchingEngine()
        : this(new RuleConditionEvaluator())
    {
    }

    /// <summary>
    /// Creates a matching engine with an injected evaluator so tests and future rule engines can share the same matching loop.
    /// </summary>
    /// <param name="conditionEvaluator">The evaluator used for safe structured operators.</param>
    public RuleMatchingEngine(IRuleConditionEvaluator conditionEvaluator)
    {
        this.conditionEvaluator = conditionEvaluator;
    }

    /// <inheritdoc />
    public RuleMatchResult Match(TrustRule rule, FactSet facts)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(facts);

        if (!rule.Enabled || rule.Mode == RuleMode.Disabled)
        {
            return new RuleMatchResult(rule, false, [], ["rule.disabled"]);
        }

        var matched = new List<string>();
        var failed = new List<string>();

        foreach (var condition in rule.Conditions)
        {
            if (!facts.TryGetValue(condition.Field, out var factValue) ||
                !conditionEvaluator.IsMatch(factValue, condition.Operator, condition.Value))
            {
                failed.Add(condition.Field);
                continue;
            }

            matched.Add(condition.Field);
        }

        return new RuleMatchResult(rule, failed.Count == 0, matched, failed);
    }
}
