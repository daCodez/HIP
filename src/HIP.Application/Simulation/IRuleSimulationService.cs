using HIP.Domain.Rules;

namespace HIP.Application.Simulation;

public interface IRuleSimulationService
{
    RuleSimulationResult Simulate(TrustRule rule, IReadOnlyCollection<RuleSimulationTestCase>? testCases);
}
