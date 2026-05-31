using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed record SelfHealingPatternDetectionResult(
    IReadOnlyCollection<PatternCluster> Clusters,
    IReadOnlyCollection<SelfHealingPatternSuggestion> Suggestions,
    string Recommendation);
