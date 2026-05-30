using HIP.Application.Rules;
using HIP.Domain.Rules;

namespace HIP.Application.Simulation;

public sealed class RuleSimulationService(IRuleActionApplier actionApplier) : IRuleSimulationService
{
    public RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase>? testCases)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var cases = testCases is { Count: > 0 } ? testCases : RuleSimulationSeedData.DefaultCases();
        if (cases.Count == 0)
        {
            throw new ArgumentException("At least one simulation test case is required.", nameof(testCases));
        }

        var results = cases.Select(testCase => Evaluate(rule, testCase)).ToArray();
        var passedCount = results.Count(result => result.Passed);
        var failedCount = results.Length - passedCount;
        var expectedPositive = cases.Count(testCase => testCase.ExpectedMatch);
        var expectedNegative = cases.Count - expectedPositive;
        var indexedResults = results.Zip(cases, (result, testCase) => new { result, testCase }).ToArray();
        var falsePositiveCount = indexedResults.Count(item => !item.testCase.ExpectedMatch && item.result.ActualMatch);
        var falseNegativeCount = indexedResults.Count(item => item.testCase.ExpectedMatch && !item.result.ActualMatch);
        var matchedKnownBad = indexedResults.Count(item => item.testCase.ExpectedMatch && item.result.ActualMatch);

        var detectionRate = expectedPositive == 0
            ? 1m
            : (expectedPositive - falseNegativeCount) / (decimal)expectedPositive;

        var falsePositiveRisk = expectedNegative == 0
            ? 0m
            : falsePositiveCount / (decimal)expectedNegative;

        var falseNegativeRisk = expectedPositive == 0
            ? 0m
            : falseNegativeCount / (decimal)expectedPositive;

        var passRate = passedCount / (decimal)cases.Count;
        var coverageScore = Math.Min(cases.Count / 10m, 1m);
        var knownBadScore = expectedPositive == 0 ? 1m : matchedKnownBad / (decimal)expectedPositive;
        var severityPenalty = IsHighImpact(rule) ? 0.05m : 0m;
        var confidence = Math.Clamp(Math.Round(
            (passRate * 0.45m) +
            (detectionRate * 0.25m) +
            ((1m - falsePositiveRisk) * 0.15m) +
            (coverageScore * 0.1m) +
            (knownBadScore * 0.05m) -
            severityPenalty,
            2),
            0m,
            1m);
        var impact = ImpactClassification(rule);
        var recommendedMode = RecommendedMode(rule, failedCount, confidence, falsePositiveRisk);
        var recommendedAction = RecommendedAction(rule, failedCount, confidence, falsePositiveRisk, falseNegativeRisk, impact);
        var failedCases = results.Where(result => !result.Passed).ToArray();
        var simulationId = $"{rule.RuleId}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}";

        return new RuleSimulationResult(
            simulationId,
            rule.RuleId,
            failedCount == 0,
            cases.Count,
            passedCount,
            failedCount,
            detectionRate,
            falsePositiveRisk,
            falseNegativeRisk,
            SpeedImpact(cases.Count),
            "Low - simulation uses anonymized facts only; no private content is required",
            confidence,
            recommendedAction,
            recommendedMode,
            impact,
            results.Where(result => result.ActualMatch).Select(_ => rule.RuleId).Distinct().ToArray(),
            failedCases,
            new RuleSimulationRollbackPlan(
                rule.RuleId,
                rule.Version > 1 ? rule.Version - 1 : null,
                failedCount > 0 || falsePositiveRisk > 0 ? "Disable or revert this rule if false positives or simulation failures occur." : "Disable this rule if production feedback shows unexpected false positives.",
                true,
                DateTimeOffset.UtcNow),
            results);
    }

    private RuleSimulationCaseResult Evaluate(TrustRule rule, RuleSimulationTestCase testCase)
    {
        var simulationRule = rule.Mode == RuleMode.Watch
            ? rule with { Mode = RuleMode.Active }
            : rule;
        var result = actionApplier.Apply(simulationRule, testCase.InputFacts);
        var failures = new List<string>();

        if (result.IsMatch != testCase.ExpectedMatch)
        {
            failures.Add($"Expected match {testCase.ExpectedMatch} but got {result.IsMatch}.");
        }

        if (testCase.ExpectedRiskLevel.HasValue && result.RiskLevel != testCase.ExpectedRiskLevel.Value)
        {
            failures.Add($"Expected risk {testCase.ExpectedRiskLevel.Value} but got {result.RiskLevel}.");
        }

        if (testCase.ExpectedSafetyPageRouting.HasValue && result.ShouldRouteToSafetyPage != testCase.ExpectedSafetyPageRouting.Value)
        {
            failures.Add($"Expected safety routing {testCase.ExpectedSafetyPageRouting.Value} but got {result.ShouldRouteToSafetyPage}.");
        }

        return new RuleSimulationCaseResult(testCase.Name, failures.Count == 0, result.IsMatch, failures.Count == 0 ? null : string.Join(" ", failures));
    }

    private static string SpeedImpact(int caseCount) => caseCount switch
    {
        <= 25 => "Low",
        <= 100 => "Medium",
        _ => "High"
    };

    private static string RecommendedMode(TrustRule rule, int failedCount, decimal confidence, decimal falsePositiveRisk)
    {
        if (failedCount > 0 || falsePositiveRisk > 0.2m)
        {
            return "disabled";
        }

        if (IsHighImpact(rule))
        {
            return "watch";
        }

        return confidence >= 0.85m ? "active" : "watch";
    }

    private static string RecommendedAction(TrustRule rule, int failedCount, decimal confidence, decimal falsePositiveRisk, decimal falseNegativeRisk, string impact)
    {
        if (failedCount > 0)
        {
            return "Do not auto-enable. Review failed cases before using this rule.";
        }

        if (falsePositiveRisk > 0.1m)
        {
            return "Keep disabled or watch-only because false-positive risk is elevated.";
        }

        if (falseNegativeRisk > 0.1m)
        {
            return "Keep in watch mode and improve coverage because false-negative risk remains.";
        }

        if (impact == "high impact" || IsHighImpact(rule))
        {
            return "RequireApproval and start in watch mode.";
        }

        return confidence >= 0.85m
            ? "May auto-enable for low-impact enforcement."
            : "Keep in watch mode until confidence improves.";
    }

    private static string ImpactClassification(TrustRule rule)
    {
        if (IsHighImpact(rule))
        {
            return "high impact";
        }

        return rule.Actions.Any(action => action.Type is RuleActionType.RequireReview or RuleActionType.SetRiskLevel)
            ? "medium impact"
            : "low impact";
    }

    private static bool IsHighImpact(TrustRule rule) =>
        rule.Severity is RuleSeverity.High or RuleSeverity.HighRisk or RuleSeverity.Dangerous or RuleSeverity.Critical ||
        rule.Actions.Any(action => action.Type is RuleActionType.Block or RuleActionType.RouteToSafetyPage);
}
