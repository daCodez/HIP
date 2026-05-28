using HIP.Application.Rules;
using HIP.Domain.Rules;

namespace HIP.Application.Simulation;

public sealed class RuleSimulationService(IRuleActionApplier actionApplier) : IRuleSimulationService
{
    public RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase> testCases)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (testCases.Count == 0)
        {
            throw new ArgumentException("At least one simulation test case is required.", nameof(testCases));
        }

        var results = testCases.Select(testCase => Evaluate(rule, testCase)).ToArray();
        var passedCount = results.Count(result => result.Passed);
        var failedCount = results.Length - passedCount;
        var expectedPositive = testCases.Count(testCase => testCase.ExpectedMatch);
        var expectedNegative = testCases.Count - expectedPositive;
        var indexedResults = results.Zip(testCases, (result, testCase) => new { result, testCase }).ToArray();
        var falsePositiveCount = indexedResults.Count(item => !item.testCase.ExpectedMatch && item.result.ActualMatch);
        var falseNegativeCount = indexedResults.Count(item => item.testCase.ExpectedMatch && !item.result.ActualMatch);

        var detectionRate = expectedPositive == 0
            ? 1m
            : (expectedPositive - falseNegativeCount) / (decimal)expectedPositive;

        var falsePositiveRisk = expectedNegative == 0
            ? 0m
            : falsePositiveCount / (decimal)expectedNegative;

        var falseNegativeRisk = expectedPositive == 0
            ? 0m
            : falseNegativeCount / (decimal)expectedPositive;

        var passRate = passedCount / (decimal)testCases.Count;
        var confidence = Math.Clamp(Math.Round((passRate * 0.7m) + (detectionRate * 0.2m) + ((1m - falsePositiveRisk) * 0.1m), 2), 0m, 1m);

        return new RuleSimulationResult(
            failedCount == 0,
            testCases.Count,
            passedCount,
            failedCount,
            detectionRate,
            falsePositiveRisk,
            falseNegativeRisk,
            "Low",
            "Low - uses provided facts only",
            confidence,
            confidence >= 0.9m && falsePositiveRisk <= 0.1m ? "Approve for active enforcement" : "Keep in watch mode",
            results);
    }

    private RuleSimulationCaseResult Evaluate(TrustRule rule, RuleSimulationTestCase testCase)
    {
        var result = actionApplier.Apply(rule, testCase.InputFacts);
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
}
