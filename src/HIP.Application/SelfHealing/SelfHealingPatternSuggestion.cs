using HIP.Domain.Risk;
using HIP.Domain.Rules;
using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed record SelfHealingPatternSuggestion(
    string PatternId,
    SelfHealingPatternType PatternType,
    decimal Confidence,
    int EvidenceCount,
    string Summary,
    RiskStatus SuggestedRiskLevel,
    string SuggestedRuleJson,
    bool SimulationRequired,
    bool ApprovalRequired,
    RuleMode RecommendedMode,
    string CandidateId);
