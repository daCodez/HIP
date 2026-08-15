namespace HIP.Application.PublicLookup;

/// <summary>Public-safe HIP lookup response for a domain.</summary>
public sealed record PublicDomainLookupResponse(
    string Domain,
    int Score,
    int FinalHipScore,
    HIP.Domain.Risk.RiskStatus Status,
    string RiskLevel,
    string VerificationStatus,
    IReadOnlyCollection<string> KnownRisks,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Explanations,
    string RecommendedAction,
    DateTimeOffset LastCheckedUtc,
    string SignedIdentityStatus,
    string VerificationMethod,
    string? VerifiedOrganization,
    string SignatureStatus,
    string IdentityVerificationStatus,
    bool? SignatureValid,
    bool PublicBadgeEligible,
    string PublicLookupUrl,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    string FinalHipScoreExplanation,
    IReadOnlyCollection<ScoreBreakdownItem> ScoreBreakdown,
    int? LinksScanned,
    int? RiskyLinksFound,
    int? SuspiciousLinksFound,
    int? DangerousLinksFound,
    string DataSource,
    string Message)
{
    /// <summary>Normalized public identity state: Unverified, Pending, or Verified.</summary>
    public string IdentityStatus => PublicEvidencePresentation.IdentityStatus(IdentityVerificationStatus);

    /// <summary>Nullable user-facing score. Null means HIP must not present the compatibility score.</summary>
    public int? DisplayScore { get; init; }

    /// <summary>
    /// Limited-evidence estimate used only by the first-party lookup experience and kept separate from authoritative scores.
    /// </summary>
    public int? ProvisionalScore =>
        DisplayScore is null && DataSource is "NoStoredData" or "VerifiedIdentityOnly"
            ? FinalHipScore
            : null;

    /// <summary>Whether numeric score presentation is available or withheld for insufficient evidence.</summary>
    public string ScorePresentation { get; init; } = PublicEvidencePresentation.ScoreWithheldInsufficientEvidence;

    /// <summary>Coverage of authenticated safety and trust evidence, separate from identity status.</summary>
    public string EvidenceCoverage { get; init; } = PublicEvidencePresentation.CoverageInsufficient;

    /// <summary>Confidence in the authenticated evidence used for public presentation.</summary>
    public string EvidenceConfidence { get; init; } = PublicEvidencePresentation.ConfidenceNone;

    /// <summary>Public-safe application decision state without reviewer identity, reasons, or private evidence.</summary>
    public string CertificateApplicationStatus { get; init; } = "NotStarted";

    /// <summary>Plain-English certificate lifecycle progress suitable for public clients.</summary>
    public string CertificateProgressStatus { get; init; } = "No certificate application";

    /// <summary>Public-safe continuous-monitoring lifecycle state.</summary>
    public string MonitoringStatus { get; init; } = "Not enabled";

    /// <summary>Optional provider-assisted wording that never replaces HIP's stored deterministic result.</summary>
    public string? AssistedExplanation { get; init; }

    /// <summary>Name of the optional explanation provider, or Deterministic when no assistance was accepted.</summary>
    public string ExplanationSource { get; init; } = "Deterministic";

    /// <summary>The exact versioned public-safe explanation stored with the authoritative assessment.</summary>
    public PublicTrustExplanation? StructuredExplanation { get; init; }
}

/// <summary>Public-safe score component used by lookup pages and API clients.</summary>
/// <param name="Category">Score category name.</param>
/// <param name="Score">Published score value.</param>
/// <param name="Status">Public risk status mapped from the stored result.</param>
/// <param name="Explanation">Plain-English public explanation.</param>
/// <param name="Reasons">Supporting public reasons.</param>
public sealed record ScoreBreakdownItem(
    string Category,
    int Score,
    HIP.Domain.Risk.RiskStatus Status,
    string Explanation,
    IReadOnlyCollection<string> Reasons);
