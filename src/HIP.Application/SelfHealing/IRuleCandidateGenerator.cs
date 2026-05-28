using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public interface IRuleCandidateGenerator
{
    GeneratedRuleCandidate Generate(PatternCluster cluster);
}
