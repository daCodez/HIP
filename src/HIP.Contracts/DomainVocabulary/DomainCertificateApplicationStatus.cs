namespace HIP.Domain.Certificates;

/// <summary>Public review state of an authenticated HIP Domain Trust Certificate application.</summary>
public enum DomainCertificateApplicationStatus
{
    /// <summary>The application has not been submitted.</summary>
    Draft = 0,

    /// <summary>The application has been submitted to HIP.</summary>
    Submitted = 1,

    /// <summary>HIP is evaluating the available application evidence.</summary>
    Evaluating = 2,

    /// <summary>The applicant must resolve one or more requirements.</summary>
    ActionRequired = 3,

    /// <summary>The application is waiting for an authorized review decision.</summary>
    PendingReview = 4,

    /// <summary>An authorized reviewer has requested changes.</summary>
    ChangesRequested = 5,

    /// <summary>The application has been approved.</summary>
    Approved = 6,

    /// <summary>The application was evaluated and denied.</summary>
    Denied = 7,

    /// <summary>The application was rejected before approval.</summary>
    Rejected = 8,

    /// <summary>The applicant withdrew the application.</summary>
    Withdrawn = 9
}
