using HIP.Application.Rules;
using HIP.Application.Simulation;
using HIP.Domain.Risk;
using HIP.Tests.Rules;

namespace HIP.Tests.Simulation;

public sealed class RuleSimulationServiceTests
{
    [Test]
    public void Simulate_calculates_confidence_from_case_results()
    {
        var service = new RuleSimulationService(new RuleActionApplier(new RuleMatchingEngine()));
        var rule = RuleEngineTests.NewDomainShortenerRule(HIP.Domain.Rules.RuleMode.Active);

        var result = service.Simulate(rule, [
            new RuleSimulationTestCase(
                "shortener to new domain",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 10, ["url.usesShortener"] = true }),
                true,
                RiskStatus.HighRisk,
                true),
            new RuleSimulationTestCase(
                "old direct domain",
                new FactSet(new Dictionary<string, object?> { ["domain.ageDays"] = 1200, ["url.usesShortener"] = false }),
                false,
                null,
                null)
        ]);

        Assert.That(result.Passed, Is.True);
        Assert.That(result.TotalTestCases, Is.EqualTo(2));
        Assert.That(result.ConfidenceScore, Is.EqualTo(1m));
        Assert.That(result.FalsePositiveRisk, Is.EqualTo(0m));
        Assert.That(result.FalseNegativeRisk, Is.EqualTo(0m));
    }
}
