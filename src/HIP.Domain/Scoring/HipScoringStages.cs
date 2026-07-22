using HIP.Domain.Risk;

namespace HIP.Domain.Scoring;

/// <summary>Whether an exact-page score was available for the requested scoring scope.</summary>
public enum HipPageTrustAvailability
{
    NotApplicable = 0,
    Available = 1,
    Missing = 2
}

/// <summary>Whether HIP may make a positive trust assertion from the evaluated evidence.</summary>
public enum HipTrustAssertionDisposition
{
    Allowed = 0,
    WithheldInsufficientEvidence = 1,
    WithheldConflictingEvidence = 2
}

/// <summary>
/// Privacy-safe scoring facts that later constraint policies can evaluate without inferring evidence
/// from already-composed numeric scores.
/// </summary>
public enum HipScoringEvidenceFactType
{
    ConfirmedMalware = 1,
    ConfirmedPhishing = 2,
    StrongExecutableDownloadRisk = 3,
    IdentityMissing = 4,
    IdentityWeak = 5,
    UnknownTarget = 6,
    LimitedEvidence = 7,
    UserGeneratedContent = 8,
    TrustedParentDomain = 9,
    RiskyExactPage = 10,
    DomainControlVerified = 11,
    OriginSignatureVerified = 12,
    HttpsTransportOnly = 13,
    StrongIdentityVerified = 14,
    ApprovedCriticalRiskOverride = 15
}

/// <summary>One typed scoring fact and its stable privacy-safe source code.</summary>
public sealed record HipScoringEvidenceFact(
    HipScoringEvidenceFactType Type,
    string SourceCode,
    DateTimeOffset? ObservedAtUtc = null,
    HipEvidencePrivacyClassification PrivacyClassification = HipEvidencePrivacyClassification.PublicMetadata);

/// <summary>
/// Bounded deterministic fact set supplied to score constraints and preserved with intermediate results.
/// It contains classifications and source codes only, never raw page content or private identifiers.
/// </summary>
public sealed class HipScoringEvidenceContext
{
    public const int MaximumFacts = 32;
    public const int MaximumSourceCodeLength = 128;

    public static HipScoringEvidenceContext Empty { get; } = new([]);

    public HipScoringEvidenceContext(IReadOnlyCollection<HipScoringEvidenceFact> facts)
    {
        ArgumentNullException.ThrowIfNull(facts);
        if (facts.Count > MaximumFacts)
        {
            throw new ArgumentOutOfRangeException(
                nameof(facts),
                $"HIP scoring accepts no more than {MaximumFacts} typed evidence facts.");
        }

        var seenTypes = new HashSet<HipScoringEvidenceFactType>();
        var identityPostureCount = 0;
        foreach (var fact in facts)
        {
            ArgumentNullException.ThrowIfNull(fact);
            if (!Enum.IsDefined(fact.Type))
            {
                throw new ArgumentOutOfRangeException(nameof(facts), "A HIP scoring evidence fact type is unsupported.");
            }

            if (!seenTypes.Add(fact.Type))
            {
                throw new ArgumentException("A HIP scoring evidence fact type can appear only once.", nameof(facts));
            }

            if (fact.Type is HipScoringEvidenceFactType.IdentityMissing or
                HipScoringEvidenceFactType.IdentityWeak or
                HipScoringEvidenceFactType.StrongIdentityVerified)
            {
                identityPostureCount++;
            }

            ValidateSourceCode(fact.SourceCode);
            if (!Enum.IsDefined(fact.PrivacyClassification))
            {
                throw new ArgumentOutOfRangeException(nameof(facts), "A HIP scoring evidence privacy classification is unsupported.");
            }
        }

        if (identityPostureCount > 1)
        {
            throw new ArgumentException(
                "A HIP scoring evidence context cannot contain contradictory identity postures.",
                nameof(facts));
        }

        Facts = Array.AsReadOnly(facts
            .OrderBy(fact => fact.Type)
            .Select(fact => fact with
            {
                SourceCode = fact.SourceCode.Trim(),
                ObservedAtUtc = fact.ObservedAtUtc?.ToUniversalTime()
            })
            .ToArray());
    }

    public IReadOnlyCollection<HipScoringEvidenceFact> Facts { get; }

    public bool Has(HipScoringEvidenceFactType type)
    {
        if (!Enum.IsDefined(type))
        {
            throw new ArgumentOutOfRangeException(nameof(type));
        }

        return Facts.Any(fact => fact.Type == type);
    }

    private static void ValidateSourceCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var trimmed = value.Trim();
        if (trimmed.Length > MaximumSourceCodeLength ||
            trimmed.Any(character =>
                character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or ':' or '-' or '_' or '.')))
        {
            throw new ArgumentException(
                "A HIP scoring evidence source must be a bounded lowercase protocol token.",
                nameof(value));
        }
    }
}

/// <summary>Typed domain-trust stage output. Higher scores mean more domain trust.</summary>
public sealed record HipDomainTrustStage
{
    private HipDomainTrustStage(ScoreValue score)
    {
        Score = score;
    }

    public ScoreValue Score { get; }

    public static HipDomainTrustStage Evaluate(int score) => new(ScoreValue.From(score));
}

/// <summary>Typed exact-page trust stage output. Higher scores mean more page trust.</summary>
public sealed record HipPageTrustStage
{
    private HipPageTrustStage(ScoreValue? score, HipPageTrustAvailability availability)
    {
        Score = score;
        Availability = availability;
    }

    public ScoreValue? Score { get; }

    public HipPageTrustAvailability Availability { get; }

    public static HipPageTrustStage Evaluate(int? score, bool pageTrustExpected)
    {
        if (score is not null)
        {
            if (!pageTrustExpected)
            {
                throw new ArgumentException(
                    "A page trust score cannot be supplied when page trust is not applicable.",
                    nameof(pageTrustExpected));
            }

            return new HipPageTrustStage(ScoreValue.From(score.Value), HipPageTrustAvailability.Available);
        }

        return new HipPageTrustStage(
            null,
            pageTrustExpected ? HipPageTrustAvailability.Missing : HipPageTrustAvailability.NotApplicable);
    }
}

/// <summary>Typed content-risk stage output. Higher scores mean more content risk.</summary>
public sealed record HipContentRiskStage
{
    private HipContentRiskStage(ScoreValue riskScore)
    {
        RiskScore = riskScore;
    }

    public ScoreValue RiskScore { get; }

    public ScoreValue InverseSafetyScore => ScoreValue.From(ScoreValue.Maximum - RiskScore.Value);

    public static HipContentRiskStage Evaluate(int riskScore) => new(ScoreValue.From(riskScore));
}

/// <summary>Typed confidence stage output kept separate from the numeric trust score.</summary>
public sealed record HipConfidenceStage
{
    private HipConfidenceStage(HipScoreConfidence level, HipEvidenceFreshness evidenceFreshness)
    {
        Level = level;
        EvidenceFreshness = evidenceFreshness;
    }

    public HipScoreConfidence Level { get; }

    public HipEvidenceFreshness EvidenceFreshness { get; }

    public static HipConfidenceStage Evaluate(
        HipScoreConfidence level,
        HipEvidenceFreshness evidenceFreshness)
    {
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }

        if (!Enum.IsDefined(evidenceFreshness))
        {
            throw new ArgumentOutOfRangeException(nameof(evidenceFreshness));
        }

        if (evidenceFreshness is HipEvidenceFreshness.Invalid)
        {
            throw new ArgumentException(
                "Invalid evidence must be rejected before HIP scoring can produce a result.",
                nameof(evidenceFreshness));
        }

        return new HipConfidenceStage(level, evidenceFreshness);
    }
}

/// <summary>Typed final-score stage output preserving both composition and constraint results.</summary>
public sealed record HipFinalScoreStage
{
    private HipFinalScoreStage(ScoreValue baselineScore, ScoreValue finalScore)
    {
        BaselineScore = baselineScore;
        Score = finalScore;
        Status = RiskStatusMapper.FromScore(finalScore);
    }

    public ScoreValue BaselineScore { get; }

    public ScoreValue Score { get; }

    public RiskStatus Status { get; }

    public static HipFinalScoreStage Evaluate(int baselineScore, int finalScore) =>
        new(ScoreValue.From(baselineScore), ScoreValue.From(finalScore));
}
