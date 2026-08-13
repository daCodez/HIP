namespace HIP.Domain.Reporting;

/// <summary>Identifies the public intent of a privacy-safe HIP report.</summary>
public enum ReportType
{
    /// <summary>Reports a URL that may present risk.</summary>
    RiskyUrl = 0,

    /// <summary>Reports a sender identity that may present risk.</summary>
    SuspiciousSender = 1,

    /// <summary>Challenges a HIP result as a possible false positive.</summary>
    FalsePositive = 2,

    /// <summary>Provides feedback that a target appears safe.</summary>
    ReportAsSafe = 3,

    /// <summary>Provides feedback that a target appears dangerous.</summary>
    ReportAsDangerous = 4,

    /// <summary>Reports a domain that may present risk.</summary>
    SuspiciousDomain = 5,

    /// <summary>Reports a suspicious content pattern without defining detection logic.</summary>
    SuspiciousContentPattern = 6
}
