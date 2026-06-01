namespace HIP.Domain.Risk;

public enum RiskStatus
{
    Unknown,
    Trusted,
    MostlyTrusted,
    LimitedTrustData,
    Suspicious,
    ProbablySafe,
    Caution,
    HighRisk,
    Dangerous,
    Critical
}
