namespace HIP.Domain.Certificates;

/// <summary>Public lifecycle state of a HIP Domain Trust Certificate.</summary>
public enum DomainCertificateStatus
{
    /// <summary>The certificate has not entered verification.</summary>
    Draft = 0,

    /// <summary>The certificate is waiting for required verification evidence.</summary>
    PendingVerification = 1,

    /// <summary>The certificate is waiting for an authorized review decision.</summary>
    PendingReview = 2,

    /// <summary>The certificate is active.</summary>
    Active = 3,

    /// <summary>The owner must resolve a certificate requirement.</summary>
    ActionRequired = 4,

    /// <summary>The certificate is temporarily suspended.</summary>
    Suspended = 5,

    /// <summary>The certificate has been revoked.</summary>
    Revoked = 6,

    /// <summary>The certificate has expired.</summary>
    Expired = 7,

    /// <summary>The certificate must be renewed before it can remain active.</summary>
    RenewalRequired = 8
}
