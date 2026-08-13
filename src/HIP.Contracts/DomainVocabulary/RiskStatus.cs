namespace HIP.Domain.Risk;

/// <summary>Identifies the public presentation status associated with a HIP trust or risk result.</summary>
public enum RiskStatus
{
    /// <summary>No status is available.</summary>
    Unknown,
    /// <summary>The result is trusted.</summary>
    Trusted,
    /// <summary>The result is mostly trusted.</summary>
    MostlyTrusted,
    /// <summary>The result has limited trust data.</summary>
    LimitedTrustData,
    /// <summary>The result is suspicious.</summary>
    Suspicious,
    /// <summary>The result is probably safe.</summary>
    ProbablySafe,
    /// <summary>The result warrants caution.</summary>
    Caution,
    /// <summary>The result has high risk.</summary>
    HighRisk,
    /// <summary>The result is dangerous.</summary>
    Dangerous,
    /// <summary>The result has critical risk.</summary>
    Critical
}
