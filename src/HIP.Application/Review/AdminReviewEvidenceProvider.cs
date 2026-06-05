using HIP.Application.SiteSafety;

namespace HIP.Application.Review;

/// <summary>
/// Converts approved admin review decisions into normalized Site Safety evidence.
/// </summary>
/// <remarks>
/// This provider is intentionally conservative. Admin review decisions are evidence that can
/// influence scoring through built-in rules, but positive decisions cannot make an unknown site
/// trusted by themselves and no raw page content is exposed.
/// </remarks>
public sealed class AdminReviewEvidenceProvider(
    IAdminReviewQueueRepository repository) : ISiteSafetyEvidenceProvider
{
    /// <inheritdoc />
    public string ProviderName => "HIP Admin Review";

    /// <inheritdoc />
    public SiteSafetyEvidenceProviderType ProviderType => SiteSafetyEvidenceProviderType.AdminReview;

    /// <inheritdoc />
    public async Task<SiteSafetyEvidence> CollectEvidenceAsync(SiteSafetyEvidenceContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var items = (await repository.ListAsync(cancellationToken))
            .Where(item => IsApplicable(item, context))
            .Select(ToEvidenceItem)
            .OfType<SiteSafetyEvidenceItem>()
            .ToArray();

        return new SiteSafetyEvidence(
            ProviderName,
            ProviderType,
            SiteSafetyEvidenceTargetType.Domain,
            context.Domain,
            context.UrlHash,
            items,
            items.Length == 0 ? 50 : Math.Clamp((int)items.Average(item => item.Confidence), 0, 100),
            context.CheckedAtUtc,
            context.CheckedAtUtc.AddMinutes(15),
            [],
            IsAuthoritativeForRisk: items.Any(item => item.Status is SiteSafetyEvidenceStatus.HighRisk or SiteSafetyEvidenceStatus.Dangerous),
            IsAuthoritativeForTrust: false);
    }

    /// <summary>
    /// Determines whether a review item should influence this scan context.
    /// </summary>
    /// <param name="item">Stored admin review item.</param>
    /// <param name="context">Current Site Safety evidence context.</param>
    /// <returns>True when the item is a resolved, matching, scored admin decision.</returns>
    private static bool IsApplicable(AdminReviewQueueItem item, SiteSafetyEvidenceContext context) =>
        item.Decision is not null and not AdminReviewDecision.NoAction &&
        (item.Status == AdminReviewStatus.Resolved ||
         item.Status == AdminReviewStatus.Escalated && item.Decision == AdminReviewDecision.NeedsMoreData) &&
        item.Domain.Equals(context.Domain, StringComparison.OrdinalIgnoreCase) &&
        (string.IsNullOrWhiteSpace(item.UrlHash) || item.UrlHash.Equals(context.UrlHash, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Converts one approved admin decision into provider-neutral evidence.
    /// </summary>
    /// <param name="item">Resolved admin review queue item.</param>
    /// <returns>Normalized evidence item, or null for decisions that should not affect scoring.</returns>
    private static SiteSafetyEvidenceItem? ToEvidenceItem(AdminReviewQueueItem item) =>
        item.Decision switch
        {
            AdminReviewDecision.ConfirmSafe => new SiteSafetyEvidenceItem(
                "AdminConfirmSafe",
                "true",
                SiteSafetyEvidenceStatus.Positive,
                RiskImpact: 0,
                TrustImpact: 3,
                "Admin review confirmed this target looked safe from privacy-safe evidence. This does not make the site trusted by itself.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 70,
                Severity: SiteSafetyEvidenceSeverity.Low,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: item.ReviewId,
                IsPositiveSignal: true),

            AdminReviewDecision.FalsePositive => new SiteSafetyEvidenceItem(
                "AdminFalsePositive",
                "true",
                SiteSafetyEvidenceStatus.Positive,
                RiskImpact: 0,
                TrustImpact: 2,
                "Admin review marked a prior risk signal as a false positive. HIP treats this as limited corrective evidence.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 65,
                Severity: SiteSafetyEvidenceSeverity.Low,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: item.ReviewId,
                IsPositiveSignal: true),

            AdminReviewDecision.ConfirmSuspicious => new SiteSafetyEvidenceItem(
                "AdminConfirmSuspicious",
                "true",
                SiteSafetyEvidenceStatus.Suspicious,
                RiskImpact: 35,
                TrustImpact: 0,
                "Admin review confirmed suspicious behavior using privacy-safe evidence.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 75,
                Severity: SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: item.ReviewId,
                IsNegativeSignal: true),

            AdminReviewDecision.ConfirmHighRisk => new SiteSafetyEvidenceItem(
                "AdminConfirmHighRisk",
                "true",
                SiteSafetyEvidenceStatus.HighRisk,
                RiskImpact: 70,
                TrustImpact: 0,
                "Admin review confirmed high-risk behavior using privacy-safe evidence.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 85,
                Severity: SiteSafetyEvidenceSeverity.High,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: item.ReviewId,
                IsNegativeSignal: true,
                IsBlockingSignal: true),

            AdminReviewDecision.ConfirmDangerous => new SiteSafetyEvidenceItem(
                "AdminConfirmDangerous",
                "true",
                SiteSafetyEvidenceStatus.Dangerous,
                RiskImpact: 90,
                TrustImpact: 0,
                "Admin review confirmed dangerous behavior using privacy-safe evidence.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 90,
                Severity: SiteSafetyEvidenceSeverity.Critical,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Strong,
                SourceReference: item.ReviewId,
                IsNegativeSignal: true,
                IsBlockingSignal: true),

            AdminReviewDecision.NeedsMoreData => new SiteSafetyEvidenceItem(
                "AdminNeedsMoreData",
                "true",
                SiteSafetyEvidenceStatus.Weak,
                RiskImpact: 0,
                TrustImpact: 0,
                "Admin review needs more privacy-safe evidence before HIP makes a stronger decision.",
                EvidenceType: "AdminReviewDecision",
                Confidence: 40,
                Severity: SiteSafetyEvidenceSeverity.Medium,
                EvidenceQuality: SiteSafetyEvidenceItemQuality.Weak,
                SourceReference: item.ReviewId),

            _ => null
        };
}
