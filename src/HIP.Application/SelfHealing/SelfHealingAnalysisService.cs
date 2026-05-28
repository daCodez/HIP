using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public sealed class SelfHealingAnalysisService(
    IPatternDetectionService patternDetectionService,
    IRuleCandidateGenerator ruleCandidateGenerator) : ISelfHealingAnalysisService
{
    public SelfHealingAnalysisResult Analyze(IReadOnlyCollection<SuspiciousFinding> findings)
    {
        var clusters = patternDetectionService.DetectPatterns(findings);
        var candidates = clusters.Select(ruleCandidateGenerator.Generate).ToArray();
        var recommendation = candidates.Any(candidate => candidate.ApprovalStatus == HIP.Domain.Rules.ApprovalStatus.Pending)
            ? "Review pending generated rules before enforcement."
            : "No high-impact generated rules require approval.";

        return new SelfHealingAnalysisResult(clusters, candidates, recommendation);
    }
}
