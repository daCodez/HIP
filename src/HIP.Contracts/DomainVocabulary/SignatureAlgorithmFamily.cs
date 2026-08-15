namespace HIP.Domain.Identity;

/// <summary>Identifies the broad cryptographic family used by a public HIP signature.</summary>
public enum SignatureAlgorithmFamily
{
    /// <summary>The signature family is unavailable or not recognized.</summary>
    Unknown,
    /// <summary>The signature uses a classical cryptographic family.</summary>
    Classical,
    /// <summary>The signature combines classical and post-quantum cryptographic families.</summary>
    Hybrid,
    /// <summary>The signature uses a post-quantum cryptographic family.</summary>
    PostQuantum
}
