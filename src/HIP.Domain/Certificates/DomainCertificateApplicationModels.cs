namespace HIP.Domain.Certificates;

/// <summary>Review state for an authenticated HIP Domain Trust Certificate application.</summary>
public enum DomainCertificateApplicationStatus
{
    Draft,
    Submitted,
    Evaluating,
    ActionRequired,
    PendingReview,
    ChangesRequested,
    Approved,
    Denied,
    Rejected,
    Withdrawn
}

/// <summary>Versioned applicant declarations required before HIP accepts a certificate application.</summary>
public static class DomainCertificateApplicantAttestation
{
    public const string Version = "hip-domain-certificate-attestation-v1";

    public const string AuthorityStatement =
        "I am authorized to submit this application for the verified domain.";

    public const string AccuracyStatement =
        "I confirm that the submitted information is accurate and may be authenticated by HIP.";
}
