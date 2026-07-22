using HIP.Domain.Scoring;

namespace HIP.Application.Scoring;

/// <summary>
/// Applies the mandatory HIP-0302 evidence caps after baseline composition. These constraints are
/// monotonic: they can preserve or lower a score, but can never turn origin or transport evidence
/// into a safety assertion.
/// </summary>
public sealed class HipMandatoryScoreConstraintPolicy : IHipScoreConstraintPolicy
{
    private const int ConfirmedThreatCap = 9;
    private const int ExecutableWithWeakIdentityCap = 39;
    private const int LimitedEvidenceCap = 69;

    public HipScoreConstraintResult Apply(HipScoreConstraintContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var baseline = context.BaselineHipScore.Value;
        var evidence = context.EvidenceContext ?? HipScoringEvidenceContext.Empty;
        var constraints = new List<ApplicableConstraint>();

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.ConfirmedMalware) ||
            evidence.Has(HipScoringEvidenceFactType.ConfirmedPhishing),
            ConfirmedThreatCap,
            () => HipScoringReasonCatalog.ConfirmedThreat(FindFirst(
                    HipScoringEvidenceFactType.ConfirmedMalware,
                    HipScoringEvidenceFactType.ConfirmedPhishing)));

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.ApprovedCriticalRiskOverride),
            ConfirmedThreatCap,
            () => HipScoringReasonCatalog.ApprovedCriticalRiskOverride(FindFirst(
                HipScoringEvidenceFactType.ApprovedCriticalRiskOverride)));

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.StrongExecutableDownloadRisk) &&
            !evidence.Has(HipScoringEvidenceFactType.StrongIdentityVerified),
            ExecutableWithWeakIdentityCap,
            () => HipScoringReasonCatalog.ExecutableWithInsufficientIdentity(
                    FindFirst(HipScoringEvidenceFactType.StrongExecutableDownloadRisk)));

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.UnknownTarget) &&
            evidence.Has(HipScoringEvidenceFactType.LimitedEvidence),
            LimitedEvidenceCap,
            () => HipScoringReasonCatalog.UnknownWithLimitedEvidence(
                    FindFirst(HipScoringEvidenceFactType.UnknownTarget)));

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.TrustedParentDomain) &&
            evidence.Has(HipScoringEvidenceFactType.RiskyExactPage),
            LimitedEvidenceCap,
            () => HipScoringReasonCatalog.TrustedParentWithRiskyPage(
                    FindFirst(HipScoringEvidenceFactType.RiskyExactPage)));

        AddIf(
            evidence.Has(HipScoringEvidenceFactType.TrustedParentDomain) &&
            evidence.Has(HipScoringEvidenceFactType.UserGeneratedContent),
            LimitedEvidenceCap,
            () => HipScoringReasonCatalog.TrustedParentWithUserGeneratedContent(
                    FindFirst(HipScoringEvidenceFactType.UserGeneratedContent)));

        if (constraints.Count == 0)
        {
            return new HipScoreConstraintResult(baseline, [], []);
        }

        return new HipScoreConstraintResult(
            constraints.Min(constraint => constraint.MaximumScore),
            constraints.Select(constraint => constraint.Entry.Explanation).ToArray(),
            constraints.Select(constraint => constraint.Entry.Warning!).ToArray(),
            constraints.Select(constraint => constraint.Entry).ToArray());

        void AddIf(bool applies, int maximumScore, Func<HipScoringReasonEntry> entryFactory)
        {
            if (applies && baseline > maximumScore)
            {
                var entry = entryFactory();
                if (entry.Impact.Kind is not HipScoreImpactKind.MaximumFinalScore ||
                    entry.Impact.Value != maximumScore)
                {
                    throw new InvalidOperationException("A score-cap catalog entry does not match its policy limit.");
                }

                constraints.Add(new ApplicableConstraint(maximumScore, entry));
            }
        }

        HipScoringEvidenceFact FindFirst(params HipScoringEvidenceFactType[] types) =>
            evidence.Facts.First(fact => types.Contains(fact.Type));
    }

    private sealed record ApplicableConstraint(
        int MaximumScore,
        HipScoringReasonEntry Entry);
}
