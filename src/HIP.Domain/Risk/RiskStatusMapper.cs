using HIP.Domain.Scoring;

namespace HIP.Domain.Risk;

public static class RiskStatusMapper
{
    public static RiskStatus FromScore(ScoreValue score) => score.Value switch
    {
        <= 9 => RiskStatus.Dangerous,
        <= 24 => RiskStatus.HighRisk,
        <= 39 => RiskStatus.Suspicious,
        <= 49 => RiskStatus.Unknown,
        <= 69 => RiskStatus.LimitedTrustData,
        <= 84 => RiskStatus.MostlyTrusted,
        _ => RiskStatus.Trusted
    };
}
