namespace HIP.Application.PublicLookup;

/// <summary>
/// Public-safe structured explanation of a stored HIP scoring result. This contract contains no rule conditions,
/// detection thresholds, private weights, raw evidence values, reporter identities, or provider-selection logic.
/// </summary>
public sealed record PublicTrustExplanation(
    string SchemaVersion,
    string ScoringPolicyVersion,
    string Confidence,
    string EvidenceFreshness,
    string TrustAssertionDisposition,
    IReadOnlyCollection<PublicTrustExplanationItem> Items);

/// <summary>One applied public scoring reason separated into evidence, analysis, impact, and action.</summary>
public sealed record PublicTrustExplanationItem(
    string ReasonCode,
    string? WarningCode,
    string? Warning,
    PublicObservedEvidence Evidence,
    string HipAnalysis,
    PublicScoreImpact ScoreImpact,
    string ConfidenceEffect,
    string RecommendedAction);

/// <summary>Minimum public metadata identifying the evidence category behind a scoring reason.</summary>
public sealed record PublicObservedEvidence(
    string Category,
    DateTimeOffset? ObservedAtUtc,
    string Classification);

/// <summary>Public score effect without internal composition weights or rule conditions.</summary>
public sealed record PublicScoreImpact(
    string Kind,
    int? Value,
    string Display);
