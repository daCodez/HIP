namespace HIP.Domain.Rules;

public enum RuleActionType
{
    SetRiskLevel,
    AdjustScore,
    AddScorePenalty,
    AddScoreBonus,
    AddReason,
    AddWarning,
    RouteToSafetyPage,
    Block,
    RequireReview,
    MarkForSimulation
}
