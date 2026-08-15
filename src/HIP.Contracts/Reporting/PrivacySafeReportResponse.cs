namespace HIP.Domain.Reporting;

/// <summary>Public lifecycle state returned for a privacy-safe report.</summary>
public enum ReportStatus
{
    /// <summary>The report was accepted for processing.</summary>
    Submitted = 0,
    /// <summary>The report is undergoing review.</summary>
    InReview = 1,
    /// <summary>The reported finding was confirmed.</summary>
    Confirmed = 2,
    /// <summary>The reported finding was rejected.</summary>
    Rejected = 3,
    /// <summary>Review requires additional privacy-safe information.</summary>
    NeedsMoreInfo = 4,
    /// <summary>The report lifecycle is complete.</summary>
    Closed = 5
}

/// <summary>Public-safe acknowledgement returned after a report submission.</summary>
public sealed record PrivacySafeReportResponse(
    bool Accepted,
    string? ReportId,
    ReportStatus Status,
    string? NormalizedDomain,
    string? UrlHash,
    string Message);
