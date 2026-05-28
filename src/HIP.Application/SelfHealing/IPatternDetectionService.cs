using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public interface IPatternDetectionService
{
    IReadOnlyCollection<PatternCluster> DetectPatterns(IReadOnlyCollection<SuspiciousFinding> findings);
}
