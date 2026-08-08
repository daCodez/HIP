namespace HIP.Domain.Certificates;

/// <summary>Public assurance level represented by a HIP Domain Trust Certificate.</summary>
public enum DomainCertificateLevel
{
    Registered,
    Verified,
    Monitored,
    Certified
}

/// <summary>Lifecycle state of a domain enrollment.</summary>
public enum DomainEnrollmentStatus
{
    Draft,
    PendingOwnership,
    OwnershipVerified,
    PendingSecurityReview,
    Verified,
    Monitored,
    Suspended,
    Revoked
}

/// <summary>Lifecycle state of a HIP Domain Trust Certificate.</summary>
public enum DomainCertificateStatus
{
    Draft,
    PendingVerification,
    PendingReview,
    Active,
    ActionRequired,
    Suspended,
    Revoked,
    Expired,
    RenewalRequired
}

/// <summary>
/// Versioned policy bounds used by certificate evaluation and lifecycle services.
/// </summary>
public sealed record DomainCertificatePolicy(
    string Version,
    TimeSpan RegisteredLifetime,
    TimeSpan VerifiedLifetime,
    TimeSpan MonitoringFreshness,
    int MinimumMonitoredTrustScore,
    int MaximumVerificationAttempts)
{
    /// <summary>Minimum HIP score required for the stronger Certified level.</summary>
    public int MinimumCertifiedTrustScore { get; init; } = 85;

    /// <summary>Whether the Verified level requires a currently valid DNSSEC chain.</summary>
    public bool RequireDnssecForVerified { get; init; }

    /// <summary>Whether the Certified level requires a currently valid DNSSEC chain.</summary>
    public bool RequireDnssecForCertified { get; init; } = true;

    /// <summary>Whether Certified issuance requires verified organization or registrant identity.</summary>
    public bool RequireIdentityForCertified { get; init; } = true;

    /// <summary>Whether Certified issuance must be routed through authorized manual review.</summary>
    public bool RequireManualReviewForCertified { get; init; } = true;

    /// <summary>Initial policy defaults for the working HIP V1 certificate implementation.</summary>
    public static DomainCertificatePolicy V1 { get; } = new(
        "hip-domain-certificate-v1",
        TimeSpan.FromDays(90),
        TimeSpan.FromDays(365),
        TimeSpan.FromDays(7),
        70,
        5);

    /// <summary>Rejects unsafe or unusable certificate policy values.</summary>
    /// <returns>The validated policy instance.</returns>
    public DomainCertificatePolicy Validate()
    {
        if (string.IsNullOrWhiteSpace(Version) ||
            Version.Length > 128 ||
            RegisteredLifetime < TimeSpan.FromDays(1) ||
            RegisteredLifetime > TimeSpan.FromDays(365) ||
            VerifiedLifetime < TimeSpan.FromDays(1) ||
            VerifiedLifetime > TimeSpan.FromDays(366) ||
            MonitoringFreshness < TimeSpan.FromHours(1) ||
            MonitoringFreshness > TimeSpan.FromDays(30) ||
            MinimumMonitoredTrustScore is < 0 or > 100 ||
            MinimumCertifiedTrustScore is < 0 or > 100 ||
            MaximumVerificationAttempts is < 1 or > 20)
        {
            throw new InvalidOperationException("HIP domain certificate policy values are outside safety bounds.");
        }

        return this;
    }
}

/// <summary>Defines and enforces the domain-enrollment state machine.</summary>
public static class DomainEnrollmentLifecycle
{
    private static readonly IReadOnlySet<(DomainEnrollmentStatus Current, DomainEnrollmentStatus Target)> Allowed =
        new HashSet<(DomainEnrollmentStatus, DomainEnrollmentStatus)>
        {
            (DomainEnrollmentStatus.Draft, DomainEnrollmentStatus.PendingOwnership),
            (DomainEnrollmentStatus.PendingOwnership, DomainEnrollmentStatus.OwnershipVerified),
            (DomainEnrollmentStatus.OwnershipVerified, DomainEnrollmentStatus.PendingSecurityReview),
            (DomainEnrollmentStatus.PendingSecurityReview, DomainEnrollmentStatus.Verified),
            (DomainEnrollmentStatus.Verified, DomainEnrollmentStatus.Monitored),
            (DomainEnrollmentStatus.Verified, DomainEnrollmentStatus.Suspended),
            (DomainEnrollmentStatus.Monitored, DomainEnrollmentStatus.Verified),
            (DomainEnrollmentStatus.Monitored, DomainEnrollmentStatus.Suspended),
            (DomainEnrollmentStatus.Suspended, DomainEnrollmentStatus.PendingOwnership),
            (DomainEnrollmentStatus.Suspended, DomainEnrollmentStatus.PendingSecurityReview)
        };

    /// <summary>Returns whether a lifecycle transition is explicitly permitted.</summary>
    public static bool CanTransition(DomainEnrollmentStatus current, DomainEnrollmentStatus target) =>
        current != DomainEnrollmentStatus.Revoked &&
        (target == DomainEnrollmentStatus.Revoked || Allowed.Contains((current, target)));

    /// <summary>Rejects an undefined, skipped, or terminal enrollment transition.</summary>
    public static void RequireTransition(DomainEnrollmentStatus current, DomainEnrollmentStatus target)
    {
        if (!CanTransition(current, target))
        {
            throw new InvalidOperationException($"Domain enrollment cannot transition from {current} to {target}.");
        }
    }
}

/// <summary>Defines and enforces the HIP Domain Trust Certificate state machine.</summary>
public static class DomainCertificateLifecycle
{
    private static readonly IReadOnlySet<(DomainCertificateStatus Current, DomainCertificateStatus Target)> Allowed =
        new HashSet<(DomainCertificateStatus, DomainCertificateStatus)>
        {
            (DomainCertificateStatus.Draft, DomainCertificateStatus.PendingVerification),
            (DomainCertificateStatus.PendingVerification, DomainCertificateStatus.PendingReview),
            (DomainCertificateStatus.PendingVerification, DomainCertificateStatus.Active),
            (DomainCertificateStatus.PendingReview, DomainCertificateStatus.Active),
            (DomainCertificateStatus.Active, DomainCertificateStatus.Suspended),
            (DomainCertificateStatus.Active, DomainCertificateStatus.ActionRequired),
            (DomainCertificateStatus.Active, DomainCertificateStatus.Expired),
            (DomainCertificateStatus.Active, DomainCertificateStatus.RenewalRequired),
            (DomainCertificateStatus.Suspended, DomainCertificateStatus.Active),
            (DomainCertificateStatus.Suspended, DomainCertificateStatus.RenewalRequired),
            (DomainCertificateStatus.ActionRequired, DomainCertificateStatus.Active),
            (DomainCertificateStatus.ActionRequired, DomainCertificateStatus.Suspended),
            (DomainCertificateStatus.ActionRequired, DomainCertificateStatus.RenewalRequired),
            (DomainCertificateStatus.ActionRequired, DomainCertificateStatus.Expired),
            (DomainCertificateStatus.RenewalRequired, DomainCertificateStatus.PendingVerification),
            (DomainCertificateStatus.RenewalRequired, DomainCertificateStatus.Expired),
            (DomainCertificateStatus.Expired, DomainCertificateStatus.PendingVerification)
        };

    /// <summary>Returns whether a lifecycle transition is explicitly permitted.</summary>
    public static bool CanTransition(DomainCertificateStatus current, DomainCertificateStatus target) =>
        current != DomainCertificateStatus.Revoked &&
        (target == DomainCertificateStatus.Revoked || Allowed.Contains((current, target)));

    /// <summary>Rejects an undefined, skipped, or terminal certificate transition.</summary>
    public static void RequireTransition(DomainCertificateStatus current, DomainCertificateStatus target)
    {
        if (!CanTransition(current, target))
        {
            throw new InvalidOperationException($"HIP Domain Trust Certificate cannot transition from {current} to {target}.");
        }
    }

    /// <summary>Requires a non-secret audit reason for manual suspension or revocation.</summary>
    public static void RequireReason(DomainCertificateStatus target, string? reason)
    {
        if (target is DomainCertificateStatus.ActionRequired or DomainCertificateStatus.Suspended or DomainCertificateStatus.Revoked &&
            string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("A reason is required for this HIP Domain Trust Certificate status change.", nameof(reason));
        }
    }
}
