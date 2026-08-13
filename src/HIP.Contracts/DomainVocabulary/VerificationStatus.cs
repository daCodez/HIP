namespace HIP.Domain.Identity;

/// <summary>Identifies the lifecycle state of publicly represented HIP verification evidence.</summary>
public enum VerificationStatus
{
    Unverified,
    Pending,
    Verified,
    Suspended,
    Revoked,
    Expired
}
