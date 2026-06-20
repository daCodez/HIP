using HIP.Application.SiteSafety;

namespace HIP.Application.Reputation;

/// <summary>
/// Converts weighted feedback aggregates into normalized Site Safety evidence.
/// </summary>
public sealed class WeightedFeedbackSiteSafetyEvidenceProvider(
    IWeightedFeedbackAggregationService aggregationService) : ISiteSafetyEvidenceProvider
{
    /// <inheritdoc />
    public string ProviderName => "HIP Weighted Feedback";

    /// <inheritdoc />
    public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.UserFeedback;

    /// <inheritdoc />
    public async Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var summary = await aggregationService.GetSummaryAsync(context.Domain, cancellationToken);
        var items = BuildItems(summary);

        return new SiteSafetyEvidence(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            items,
            summary.ConfidenceImpact > 0 ? 40 : 60,
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(15),
            [],
            IsAuthoritativeForRisk: false,
            IsAuthoritativeForTrust: false);
    }

    /// <summary>
    /// Builds provider evidence items from aggregated feedback without claiming proof.
    /// </summary>
    /// <param name="summary">Privacy-safe weighted feedback totals for one domain.</param>
    /// <returns>Normalized evidence items that the Site Safety scanner can score conservatively.</returns>
    private static IReadOnlyCollection<SiteSafetyEvidenceItem> BuildItems(WeightedFeedbackSummary summary)
    {
        var items = new List<SiteSafetyEvidenceItem>();
        if (summary.LooksSafeWeight > 0)
        {
            items.Add(new SiteSafetyEvidenceItem(
                "LooksSafe",
                summary.LooksSafeWeight.ToString(),
                SiteSafetyEvidenceStatus.Positive,
                0,
                Math.Min(3, Math.Max(1, summary.LooksSafeWeight / 5)),
                "Trusted feedback suggests this warning may be too strong, but feedback alone does not prove safety.",
                EvidenceType: "WeightedFeedback",
                Confidence: 35,
                Severity: SiteSafetyEvidenceSeverity.Info,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak,
                IsPositiveSignal: true));
        }

        if (summary.LooksSuspiciousWeight > 0 || summary.ReportIssueWeight > 0)
        {
            var riskWeight = summary.LooksSuspiciousWeight + summary.ReportIssueWeight;
            items.Add(new SiteSafetyEvidenceItem(
                "LooksSuspicious",
                riskWeight.ToString(),
                riskWeight >= 12 ? SiteSafetyEvidenceStatus.HighRisk : SiteSafetyEvidenceStatus.Suspicious,
                Math.Min(35, Math.Max(3, riskWeight * 2)),
                0,
                "Some users have reported this site as suspicious, but HIP has not confirmed a threat.",
                EvidenceType: "WeightedFeedback",
                Confidence: 35,
                Severity: riskWeight >= 12 ? SiteSafetyEvidenceSeverity.Medium : SiteSafetyEvidenceSeverity.Low,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak,
                IsNegativeSignal: true));
        }

        if (summary.ConflictingFeedbackSpike)
        {
            items.Add(new SiteSafetyEvidenceItem(
                "ConflictingFeedback",
                summary.ConfidenceImpact.ToString(),
                SiteSafetyEvidenceStatus.Weak,
                0,
                0,
                "Recent feedback is conflicting, so HIP lowered confidence and recommends review.",
                EvidenceType: "WeightedFeedback",
                Confidence: 30,
                Severity: SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak));
        }

        if (summary.RecommendedReview)
        {
            items.Add(new SiteSafetyEvidenceItem(
                "AdminReviewSignal",
                "true",
                SiteSafetyEvidenceStatus.Weak,
                0,
                0,
                "Feedback patterns recommend admin review before HIP changes trust significantly.",
                EvidenceType: "WeightedFeedback",
                Confidence: 30,
                Severity: SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak));
        }

        return items;
    }
}
