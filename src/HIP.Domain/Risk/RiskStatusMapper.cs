using HIP.Domain.Scoring;

namespace HIP.Domain.Risk;

public static class RiskStatusMapper
{
    public static RiskStatus FromScore(ScoreValue score) => score.Value switch
    {
        <= 20 => RiskStatus.Dangerous,
        <= 40 => RiskStatus.HighRisk,
        <= 60 => RiskStatus.Caution,
        <= 80 => RiskStatus.ProbablySafe,
        _ => RiskStatus.Trusted
    };
}
