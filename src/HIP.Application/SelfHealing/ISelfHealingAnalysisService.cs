using HIP.Domain.SelfHealing;

namespace HIP.Application.SelfHealing;

public interface ISelfHealingAnalysisService
{
    SelfHealingAnalysisResult Analyze(IReadOnlyCollection<SuspiciousFinding> findings);
}
