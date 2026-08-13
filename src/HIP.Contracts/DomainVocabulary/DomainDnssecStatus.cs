namespace HIP.Domain.Domains;

/// <summary>Describes the observed DNSSEC condition for a domain.</summary>
public enum DomainDnssecStatus
{
    /// <summary>HIP has no conclusive DNSSEC observation.</summary>
    Unknown = 0,

    /// <summary>The domain or its DNS provider does not support DNSSEC.</summary>
    Unsupported = 1,

    /// <summary>DNSSEC is not enabled for the domain.</summary>
    Disabled = 2,

    /// <summary>The DNSSEC validation chain is valid.</summary>
    Valid = 3,

    /// <summary>The DNSSEC validation chain is invalid.</summary>
    Invalid = 4,

    /// <summary>DNSSEC is present but configured incorrectly.</summary>
    Misconfigured = 5
}
