using HIP.Domain.Risk;
using HIP.Domain.Rules;

namespace HIP.Application.Rules;

public sealed record AppliedRuleResult(
    TrustRule Rule,
    bool IsMatch,
    RiskStatus RiskLevel,
    int ScoreDelta,
    IReadOnlyCollection<string> Reasons,
    bool ShouldRouteToSafetyPage,
    bool RequiresReview,
    bool MarkedForSimulation);
