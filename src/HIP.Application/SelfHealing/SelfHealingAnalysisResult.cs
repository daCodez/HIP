using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed record SelfHealingAnalysisResult(
    IReadOnlyCollection<PatternCluster> Clusters,
    IReadOnlyCollection<GeneratedRuleCandidate> GeneratedRuleCandidates,
    string Recommendation);
