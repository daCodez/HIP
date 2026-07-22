namespace HIP.Domain.Scoring;

/// <summary>Privacy classification for bounded scoring metadata that is safe to publish.</summary>
public enum HipEvidencePrivacyClassification
{
    /// <summary>Public facts such as a provider-neutral rule or evidence classification.</summary>
    PublicMetadata = 0,

    /// <summary>Privacy-safe metadata derived by HIP without retaining raw source content.</summary>
    DerivedMetadata = 1
}

/// <summary>How a catalog entry affects or constrains the final HIP score.</summary>
public enum HipScoreImpactKind
{
    /// <summary>The entry explains confidence or evidence state without changing a numeric score.</summary>
    None = 0,

    /// <summary>The entry places an upper bound on the final HIP score.</summary>
    MaximumFinalScore = 1,

    /// <summary>The entry records a direct final-score delta.</summary>
    ScoreDelta = 2,

    /// <summary>The entry records an increase to a higher-is-risk component.</summary>
    RiskScoreIncrease = 3,

    /// <summary>The entry records a delta to a higher-is-trust component.</summary>
    TrustScoreDelta = 4
}

/// <summary>Typed score impact carried by one stable scoring reason.</summary>
public sealed record HipScoreImpact
{
    /// <summary>Creates a validated impact whose value semantics match its kind.</summary>
    public HipScoreImpact(HipScoreImpactKind kind, int? value)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        var valid = kind switch
        {
            HipScoreImpactKind.None => value is null,
            HipScoreImpactKind.MaximumFinalScore => value is >= ScoreValue.Minimum and <= ScoreValue.Maximum,
            HipScoreImpactKind.ScoreDelta => value is >= -ScoreValue.Maximum and <= ScoreValue.Maximum,
            HipScoreImpactKind.RiskScoreIncrease => value is > ScoreValue.Minimum and <= ScoreValue.Maximum,
            HipScoreImpactKind.TrustScoreDelta => value is >= -ScoreValue.Maximum and <= ScoreValue.Maximum && value != 0,
            _ => false
        };
        if (!valid)
        {
            throw new ArgumentException("The score impact value is inconsistent with its impact kind.", nameof(value));
        }

        Kind = kind;
        Value = value;
    }

    /// <summary>Gets the interpretation applied to <see cref="Value"/>.</summary>
    public HipScoreImpactKind Kind { get; }

    /// <summary>Gets the bounded impact value, or null only when <see cref="Kind"/> is <see cref="HipScoreImpactKind.None"/>.</summary>
    public int? Value { get; }
}

/// <summary>
/// One version-stable, privacy-safe reason catalog entry. Existing plain-language projections remain
/// available separately for compatibility, while this contract gives clients a durable identifier.
/// </summary>
public sealed class HipScoringReasonEntry
{
    /// <summary>Maximum supported reason, warning, or protocol code length.</summary>
    public const int MaximumCodeLength = 128;

    /// <summary>Maximum supported plain-language explanation or warning length.</summary>
    public const int MaximumMessageLength = 512;

    /// <summary>Maximum supported evidence source token length.</summary>
    public const int MaximumSourceCodeLength = 128;

    /// <summary>Creates one validated immutable reason catalog entry.</summary>
    public HipScoringReasonEntry(
        string code,
        string explanation,
        string? warningCode,
        string? warning,
        HipScoreImpact impact,
        string evidenceSourceCode,
        DateTimeOffset? evidenceObservedAtUtc,
        HipEvidencePrivacyClassification privacyClassification)
    {
        Code = RequiredCode(code, nameof(code), MaximumCodeLength);
        Explanation = RequiredMessage(explanation, nameof(explanation));
        if (string.IsNullOrWhiteSpace(warningCode) != string.IsNullOrWhiteSpace(warning))
        {
            throw new ArgumentException("A scoring warning code and warning message must be supplied together.", nameof(warningCode));
        }

        WarningCode = warningCode is null
            ? null
            : RequiredCode(warningCode, nameof(warningCode), MaximumCodeLength);
        Warning = warning is null ? null : RequiredMessage(warning, nameof(warning));
        Impact = impact ?? throw new ArgumentNullException(nameof(impact));
        EvidenceSourceCode = RequiredCode(
            evidenceSourceCode,
            nameof(evidenceSourceCode),
            MaximumSourceCodeLength);
        EvidenceObservedAtUtc = evidenceObservedAtUtc?.ToUniversalTime();
        if (!Enum.IsDefined(privacyClassification))
        {
            throw new ArgumentOutOfRangeException(nameof(privacyClassification));
        }

        PrivacyClassification = privacyClassification;
    }

    /// <summary>Gets the version-stable machine-readable reason code.</summary>
    public string Code { get; }

    /// <summary>Gets the bounded plain-language explanation.</summary>
    public string Explanation { get; }

    /// <summary>Gets the optional version-stable warning code.</summary>
    public string? WarningCode { get; }

    /// <summary>Gets the optional bounded plain-language warning.</summary>
    public string? Warning { get; }

    /// <summary>Gets the explicit score impact semantics.</summary>
    public HipScoreImpact Impact { get; }

    /// <summary>Gets the privacy-safe source token for the supporting evidence.</summary>
    public string EvidenceSourceCode { get; }

    /// <summary>Gets the UTC evidence time when the source supplied one.</summary>
    public DateTimeOffset? EvidenceObservedAtUtc { get; }

    /// <summary>Gets the public-safe privacy classification.</summary>
    public HipEvidencePrivacyClassification PrivacyClassification { get; }

    private static string RequiredCode(string value, string parameterName, int maximumLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var trimmed = value.Trim();
        if (trimmed.Length > maximumLength ||
            trimmed.Any(character =>
                character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or ':' or '-' or '_' or '.')))
        {
            throw new ArgumentException("A scoring catalog code must be a bounded lowercase protocol token.", parameterName);
        }

        return trimmed;
    }

    private static string RequiredMessage(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var trimmed = value.Trim();
        if (trimmed.Length > MaximumMessageLength || trimmed.Any(char.IsControl))
        {
            throw new ArgumentException("A scoring catalog message must be bounded plain text.", parameterName);
        }

        return trimmed;
    }
}
