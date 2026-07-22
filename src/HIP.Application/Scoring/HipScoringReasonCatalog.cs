using HIP.Domain.Scoring;
using System.Security.Cryptography;
using System.Text;

namespace HIP.Application.Scoring;

/// <summary>
/// Creates the version-stable HIP-0303 catalog entries used by mandatory score constraints.
/// Codes are protocol identifiers; changing their text requires an explicit compatibility migration.
/// </summary>
public static class HipScoringReasonCatalog
{
    /// <summary>Creates a deterministic entry for one enforced score-changing Site Safety rule.</summary>
    public static HipScoringReasonEntry RuleSignal(
        string ruleId,
        string explanation,
        string? warning,
        HipScoreImpact impact)
    {
        var identifier = CanonicalRuleIdentifier(ruleId);
        return new HipScoringReasonEntry(
            $"rule:{identifier}",
            explanation,
            warning is null ? null : $"rule-warning:{identifier}",
            warning,
            impact,
            $"site-safety:rule:{identifier}",
            null,
            HipEvidencePrivacyClassification.DerivedMetadata);
    }

    /// <summary>Creates the stable warning entry used when exact-page evidence is unavailable.</summary>
    public static HipScoringReasonEntry MissingPageEvidence() => WarningOnly(
        "evidence:page-missing",
        "Page-specific trust evidence was unavailable for this scoring scope.",
        "warning:page-missing",
        "No page-specific trust score was available; HIP normalized the active domain and content weights.",
        "scoring:page-evidence");

    /// <summary>Creates the stable warning entry used when required evidence is missing.</summary>
    public static HipScoringReasonEntry MissingEvidenceFreshness() => WarningOnly(
        "evidence:freshness-missing",
        "Required scoring evidence was missing.",
        "warning:evidence-freshness-missing",
        "Required evidence is missing; HIP withheld a positive trust assertion.",
        "scoring:evidence-freshness");

    /// <summary>Creates the stable warning entry used when evidence freshness is mixed.</summary>
    public static HipScoringReasonEntry MixedEvidenceFreshness() => WarningOnly(
        "evidence:freshness-mixed",
        "Scoring evidence had mixed freshness.",
        "warning:evidence-freshness-mixed",
        "Evidence freshness is mixed; HIP withheld a positive trust assertion.",
        "scoring:evidence-freshness");

    /// <summary>Creates the stable warning entry used when evidence is stale.</summary>
    public static HipScoringReasonEntry StaleEvidenceFreshness() => WarningOnly(
        "evidence:freshness-stale",
        "Scoring evidence was stale.",
        "warning:evidence-freshness-stale",
        "Evidence is stale; HIP withheld a positive trust assertion.",
        "scoring:evidence-freshness");

    /// <summary>Creates the stable warning entry used when evidence confidence is low.</summary>
    public static HipScoringReasonEntry LowConfidence() => WarningOnly(
        "confidence:low",
        "The available evidence produced low scoring confidence.",
        "warning:confidence-low",
        "Evidence confidence is low; HIP withheld a positive trust assertion.",
        "scoring:confidence");

    /// <summary>Creates the stable warning entry used when evidence conflicts.</summary>
    public static HipScoringReasonEntry ConflictedConfidence() => WarningOnly(
        "confidence:conflicted",
        "The available scoring evidence conflicted.",
        "warning:confidence-conflicted",
        "Evidence conflicts; HIP withheld a positive trust assertion pending review.",
        "scoring:confidence");

    /// <summary>Creates the mandatory confirmed-threat score-cap entry.</summary>
    public static HipScoringReasonEntry ConfirmedThreat(HipScoringEvidenceFact evidence) => Create(
        "score-cap:confirmed-threat",
        "Confirmed malware or phishing evidence limits the final HIP score to 9.",
        "warning:confirmed-threat",
        "Confirmed threat evidence overrides otherwise positive trust signals.",
        9,
        evidence);

    /// <summary>Creates the approved critical-risk override entry without misclassifying it as threat evidence.</summary>
    public static HipScoringReasonEntry ApprovedCriticalRiskOverride(HipScoringEvidenceFact evidence) => Create(
        "score-cap:approved-critical-risk-override",
        "An approved critical risk override limits the final HIP score to 9.",
        "warning:approved-critical-risk-override",
        "An approved critical rule overrides otherwise positive trust signals.",
        9,
        evidence);

    /// <summary>Creates the mandatory executable-risk and insufficient-identity score-cap entry.</summary>
    public static HipScoringReasonEntry ExecutableWithInsufficientIdentity(HipScoringEvidenceFact evidence) => Create(
        "score-cap:executable-weak-identity",
        "Strong executable-download risk with missing or weak identity limits the final HIP score to 39.",
        "warning:executable-weak-identity",
        "The executable download lacks sufficiently strong identity evidence.",
        39,
        evidence);

    /// <summary>Creates the mandatory unknown-target and limited-evidence score-cap entry.</summary>
    public static HipScoringReasonEntry UnknownWithLimitedEvidence(HipScoringEvidenceFact evidence) => Create(
        "score-cap:unknown-limited-evidence",
        "An unknown target with limited evidence cannot exceed a final HIP score of 69.",
        "warning:unknown-limited-evidence",
        "HIP has too little evidence to make a positive trust assertion for this target.",
        69,
        evidence);

    /// <summary>Creates the mandatory trusted-parent and risky-exact-page score-cap entry.</summary>
    public static HipScoringReasonEntry TrustedParentWithRiskyPage(HipScoringEvidenceFact evidence) => Create(
        "score-cap:trusted-parent-risky-page",
        "A trusted parent domain cannot hide risk on the exact page; the final HIP score is limited to 69.",
        "warning:trusted-parent-risky-page",
        "Risk on the exact page takes precedence over the parent domain's reputation.",
        69,
        evidence);

    /// <summary>Creates the mandatory trusted-parent and user-generated-content score-cap entry.</summary>
    public static HipScoringReasonEntry TrustedParentWithUserGeneratedContent(HipScoringEvidenceFact evidence) => Create(
        "score-cap:trusted-parent-user-generated",
        "A user-generated area cannot inherit the trusted parent domain's full page score; the final HIP score is limited to 69.",
        "warning:trusted-parent-user-generated",
        "The exact page needs independent evidence because its content is user-generated.",
        69,
        evidence);

    private static HipScoringReasonEntry Create(
        string code,
        string explanation,
        string warningCode,
        string warning,
        int maximumFinalScore,
        HipScoringEvidenceFact evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        return new HipScoringReasonEntry(
            code,
            explanation,
            warningCode,
            warning,
            new HipScoreImpact(HipScoreImpactKind.MaximumFinalScore, maximumFinalScore),
            evidence.SourceCode,
            evidence.ObservedAtUtc,
            evidence.PrivacyClassification);
    }

    private static HipScoringReasonEntry WarningOnly(
        string code,
        string explanation,
        string warningCode,
        string warning,
        string evidenceSourceCode) => new(
        code,
        explanation,
        warningCode,
        warning,
        new HipScoreImpact(HipScoreImpactKind.None, null),
        evidenceSourceCode,
        null,
        HipEvidencePrivacyClassification.DerivedMetadata);

    private static string CanonicalRuleIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var original = value.Trim();
        var slug = new string(original
            .ToLowerInvariant()
            .Select(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.'
                    ? character
                    : '-')
            .ToArray()).Trim('-', '.', '_');
        if (slug.Length == 0)
        {
            slug = "unknown";
        }

        const int maximumIdentifierLength = 96;
        if (slug.Length <= maximumIdentifierLength &&
            string.Equals(slug, original, StringComparison.Ordinal))
        {
            return slug;
        }

        var suffix = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(original)))
            .ToLowerInvariant()[..8];
        var prefixLength = maximumIdentifierLength - suffix.Length - 1;
        if (slug.Length > prefixLength)
        {
            slug = slug[..prefixLength];
        }

        return $"{slug}-{suffix}";
    }
}
