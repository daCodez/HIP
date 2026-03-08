using HIP.Security.Domain.Scenarios;
using HIP.Security.Infrastructure.Repositories;
using HIP.Security.PolicyEngine.Execution;

namespace HIP.Security.Tests;

public class CoverageEvaluatorTests
{
    [Test]
    public async Task EvaluateCoverage_ShouldReturnReport()
    {
        var scenarioRepository = new InMemoryScenarioRepository();
        await scenarioRepository.AddAsync(new ThreatScenario(
            Guid.NewGuid(),
            "Replay attack",
            "Basic replay attack scenario",
            ["Capture token", "Replay token"],
            ["replay"],
            DateTimeOffset.UtcNow));

        var evaluator = new BasicCoverageEvaluator(scenarioRepository);
        var report = await evaluator.EvaluateAsync(Guid.NewGuid());

        Assert.That(report.TotalScenarios, Is.EqualTo(1));
    }
}
