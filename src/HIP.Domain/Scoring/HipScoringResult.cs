using HIP.Domain.Risk;

namespace HIP.Domain.Scoring;

/// <summary>Confidence in the evidence behind a HIP score; confidence never changes the numeric score.</summary>
public enum HipScoreConfidence
{
    Low = 0,
    Medium = 1,
    High = 2,
    Conflicted = 3
}

/// <summary>Freshness of the bounded evidence set used by the scoring pipeline.</summary>
public enum HipEvidenceFreshness
{
    Missing = 0,
    Fresh = 1,
    Mixed = 2,
    Stale = 3,
    Invalid = 4
}

/// <summary>
/// Versioned, direction-explicit result from the formal HIP scoring pipeline.
/// Domain, page, and final scores are trust scores; content is a risk score.
/// </summary>
public sealed class HipScoringResult
{
    public const string CurrentModelVersion = "hip-0301-v1";

    /// <summary>Maximum typed reason entries published with one formal score.</summary>
    public const int MaximumReasonEntries = 32;

    public HipScoringResult(
        HipDomainTrustStage domainTrust,
        HipPageTrustStage pageTrust,
        HipContentRiskStage contentRisk,
        HipFinalScoreStage finalScore,
        HipConfidenceStage confidence,
        HipTrustAssertionDisposition trustAssertionDisposition,
        IReadOnlyCollection<string> reasons,
        IReadOnlyCollection<string> warnings,
        HipScoringEvidenceContext? evidenceContext = null,
        IReadOnlyCollection<HipScoringReasonEntry>? reasonEntries = null)
    {
        ArgumentNullException.ThrowIfNull(domainTrust);
        ArgumentNullException.ThrowIfNull(pageTrust);
        ArgumentNullException.ThrowIfNull(contentRisk);
        ArgumentNullException.ThrowIfNull(finalScore);
        ArgumentNullException.ThrowIfNull(confidence);
        if (!Enum.IsDefined(trustAssertionDisposition))
        {
            throw new ArgumentOutOfRangeException(nameof(trustAssertionDisposition));
        }

        ArgumentNullException.ThrowIfNull(reasons);
        ArgumentNullException.ThrowIfNull(warnings);
        if (reasons.Count == 0 || reasons.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException(
                "A HIP scoring result requires at least one plain-language reason.",
                nameof(reasons));
        }

        if (warnings.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("HIP scoring warnings cannot be blank.", nameof(warnings));
        }

        DomainTrust = domainTrust;
        PageTrust = pageTrust;
        ContentRisk = contentRisk;
        FinalScore = finalScore;
        ConfidenceStage = confidence;
        TrustAssertionDisposition = trustAssertionDisposition;
        EvidenceContext = evidenceContext ?? HipScoringEvidenceContext.Empty;
        Reasons = Array.AsReadOnly(reasons.Select(reason => reason.Trim()).ToArray());
        Warnings = Array.AsReadOnly(warnings.Select(warning => warning.Trim()).ToArray());
        var entries = reasonEntries ?? Array.Empty<HipScoringReasonEntry>();
        if (entries.Count > MaximumReasonEntries)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reasonEntries),
                $"A HIP scoring result accepts no more than {MaximumReasonEntries} reason entries.");
        }

        if (entries.Any(entry => entry is null) ||
            entries.Select(entry => entry.Code).Distinct(StringComparer.Ordinal).Count() != entries.Count)
        {
            throw new ArgumentException("HIP scoring reason entries must be non-null with unique stable codes.", nameof(reasonEntries));
        }

        ReasonEntries = Array.AsReadOnly(entries.ToArray());
    }

    public string ModelVersion => CurrentModelVersion;

    public HipDomainTrustStage DomainTrust { get; }

    public HipPageTrustStage PageTrust { get; }

    public HipContentRiskStage ContentRisk { get; }

    public HipFinalScoreStage FinalScore { get; }

    public HipConfidenceStage ConfidenceStage { get; }

    public int DomainTrustScore => DomainTrust.Score.Value;

    public int? PageTrustScore => PageTrust.Score?.Value;

    public int ContentRiskScore => ContentRisk.RiskScore.Value;

    public int FinalHipScore => FinalScore.Score.Value;

    public RiskStatus FinalStatus => FinalScore.Status;

    public HipScoreConfidence Confidence => ConfidenceStage.Level;

    public HipEvidenceFreshness EvidenceFreshness => ConfidenceStage.EvidenceFreshness;

    public HipTrustAssertionDisposition TrustAssertionDisposition { get; }

    /// <summary>Typed privacy-safe inputs preserved for later cap, override, and reason policies.</summary>
    public HipScoringEvidenceContext EvidenceContext { get; }

    /// <summary>
    /// Conservative status for user-facing surfaces. Known risk is preserved, while a positive
    /// result is withheld when the supporting evidence is insufficient or contradictory.
    /// </summary>
    public RiskStatus PresentationStatus => FinalHipScore < 50
        ? FinalStatus
        : TrustAssertionDisposition switch
        {
            HipTrustAssertionDisposition.Allowed => FinalStatus,
            HipTrustAssertionDisposition.WithheldConflictingEvidence => RiskStatus.Unknown,
            _ => RiskStatus.LimitedTrustData
        };

    public bool CanAssertPositiveTrust =>
        FinalHipScore >= 70 && TrustAssertionDisposition is HipTrustAssertionDisposition.Allowed;

    public IReadOnlyCollection<string> Reasons { get; }

    public IReadOnlyCollection<string> Warnings { get; }

    /// <summary>Stable typed catalog entries for formal system-generated scoring reasons.</summary>
    public IReadOnlyCollection<HipScoringReasonEntry> ReasonEntries { get; }

    public bool FinalScoreHigherMeansMoreTrust => true;

    public bool ContentRiskScoreHigherMeansMoreRisk => true;
}
