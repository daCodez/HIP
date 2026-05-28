using HIP.Application.Rules;
using HIP.Domain.Risk;

namespace HIP.Application.Simulation;

public sealed record RuleSimulationTestCase(
    string Name,
    FactSet InputFacts,
    bool ExpectedMatch,
    RiskStatus? ExpectedRiskLevel,
    bool? ExpectedSafetyPageRouting);
