using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public interface ISelfHealingPatternDetectionService
{
    Task<SelfHealingPatternDetectionResult> DetectAsync(
        IReadOnlyCollection<SuspiciousFinding> findings,
        CancellationToken cancellationToken);

    Task<SelfHealingPatternSuggestion> GenerateRuleAsync(
        PatternCluster cluster,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<GeneratedRuleCandidate>> ListSuggestionsAsync(CancellationToken cancellationToken);

    Task<GeneratedRuleCandidate?> ApproveSuggestionAsync(string candidateId, CancellationToken cancellationToken);

    Task<GeneratedRuleCandidate?> RejectSuggestionAsync(string candidateId, CancellationToken cancellationToken);
}
