namespace HIP.Domain.Identity;

/// <summary>Identifies the lifecycle state of publicly represented HIP verification evidence.</summary>
public enum VerificationStatus
{
    /// <summary>No verification has been established.</summary>
    Unverified,
    /// <summary>Verification is awaiting completion.</summary>
    Pending,
    /// <summary>Verification is active.</summary>
    Verified,
    /// <summary>Verification is temporarily suspended.</summary>
    Suspended,
    /// <summary>Verification has been revoked.</summary>
    Revoked,
    /// <summary>Verification has expired.</summary>
    Expired
}
