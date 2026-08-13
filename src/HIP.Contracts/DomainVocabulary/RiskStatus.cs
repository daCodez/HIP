namespace HIP.Domain.Risk;

/// <summary>Identifies the public presentation status associated with a HIP trust or risk result.</summary>
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
