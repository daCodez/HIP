using HIP.Application.Browser;
using HIP.Application.Reputation;
using HIP.Application.Review;
using HIP.Application.SiteSafety;

namespace HIP.Application.Scans;

/// <summary>
/// Provides read-only admin scan details without exposing raw URLs, page text, form values, or private content.
/// </summary>
public interface IAdminScanDetailService
{
    /// <summary>
    /// Gets a privacy-safe admin scan detail record for a stored browser scan.
    /// </summary>
    /// <param name="scanId">Stored browser scan identifier.</param>
    /// <param name="cancellationToken">Token used to cancel lookup and scoring work.</param>
    /// <returns>Scan details, or null when the scan ID is unknown.</returns>
    Task<AdminScanDetail?> GetAsync(string scanId, CancellationToken cancellationToken);
}

/// <summary>
/// Privacy-safe admin detail view for one stored browser scan result.
/// </summary>
/// <param name="ScanId">Stored scan identifier.</param>
/// <param name="Domain">Normalized domain.</param>
/// <param name="UrlHash">One-way page URL hash. The raw page URL is intentionally not exposed.</param>
/// <param name="TargetType">Target scope for this scan.</param>
/// <param name="ScannedAtUtc">UTC scan time from the stored browser scan.</param>
/// <param name="FinalStatus">Stored final status label.</param>
/// <param name="SiteSafetyStatus">Re-evaluated Site Safety status label.</param>
/// <param name="DomainTrustScore">Root-domain trust score.</param>
/// <param name="PageTrustScore">Exact-page trust score.</param>
/// <param name="ContentRiskScore">Content trust score, where lower values indicate more risk.</param>
/// <param name="FinalHipScore">Final user-facing HIP score from the detail evaluation.</param>
/// <param name="ConfidenceLevel">Confidence label for the detail evaluation.</param>
/// <param name="Summary">Plain-English scan summary.</param>
/// <param name="Reasons">Plain-English reasons.</param>
/// <param name="Warnings">Warnings that may require admin attention.</param>
/// <param name="PositiveSignals">Positive signals observed without overclaiming trust.</param>
/// <param name="NegativeSignals">Negative signals that reduced trust or confidence.</param>
/// <param name="MatchedRules">Built-in and admin rules matched by the privacy-safe re-evaluation.</param>
/// <param name="ProviderEvidence">Normalized provider evidence used by scoring.</param>
/// <param name="FeedbackEvidence">Weighted feedback evidence when available. This is not voting.</param>
/// <param name="ReviewStatus">Related admin review state when available.</param>
public sealed record AdminScanDetail(
    string ScanId,
    string Domain,
    string UrlHash,
    string TargetType,
    DateTimeOffset ScannedAtUtc,
    string FinalStatus,
    string SiteSafetyStatus,
    int DomainTrustScore,
    int PageTrustScore,
    int ContentRiskScore,
    int FinalHipScore,
    string ConfidenceLevel,
    string Summary,
    IReadOnlyCollection<string> Reasons,
    IReadOnlyCollection<string> Warnings,
    IReadOnlyCollection<string> PositiveSignals,
    IReadOnlyCollection<string> NegativeSignals,
    IReadOnlyCollection<AdminScanMatchedRuleDetail> MatchedRules,
    IReadOnlyCollection<AdminScanProviderEvidenceDetail> ProviderEvidence,
    AdminScanFeedbackEvidenceDetail? FeedbackEvidence,
    AdminScanReviewStatusDetail? ReviewStatus);

/// <summary>
/// Privacy-safe matched rule explanation for admin scan details.
/// </summary>
public sealed record AdminScanMatchedRuleDetail(
    string RuleId,
    string RuleName,
    string Source,
    string Severity,
    string Mode,
    string Status,
    string Reason,
    string? Warning,
    int RiskImpact,
    int TrustImpact,
    string? StatusOverride);

/// <summary>
/// Provider evidence summary safe for admin display.
/// </summary>
public sealed record AdminScanProviderEvidenceDetail(
    string ProviderName,
    string ProviderType,
    int Confidence,
    string EvidenceQuality,
    string Summary,
    int RiskImpact,
    int TrustImpact,
    IReadOnlyCollection<string> Errors,
    DateTimeOffset CheckedAtUtc,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// Weighted feedback summary for scan details. HIP treats this as weak trust evidence, not voting.
/// </summary>
public sealed record AdminScanFeedbackEvidenceDetail(
    int LooksSafeWeightedTotal,
    int LooksSuspiciousWeightedTotal,
    int ReportIssueWeightedTotal,
    string ReporterTrustSummary,
    int ConfidenceImpact,
    bool ReviewRecommended,
    IReadOnlyCollection<string> Explanations);

/// <summary>
/// Related admin review state for a scan detail page.
/// </summary>
public sealed record AdminScanReviewStatusDetail(
    string ReviewId,
    string Status,
    string Severity,
    string Source,
    string Summary,
    string? Decision,
    string? DecisionReason);

/// <summary>
/// Builds privacy-safe admin scan detail responses from stored browser scans and current Site Safety rules.
/// </summary>
public sealed class AdminScanDetailService(
    IBrowserScanResultRepository scanResultRepository,
    ISiteSafetyScanner siteSafetyScanner,
    IWeightedFeedbackAggregationService feedbackAggregationService,
    IAdminReviewQueueRepository reviewQueueRepository) : IAdminScanDetailService
{
    /// <inheritdoc />
    public async Task<AdminScanDetail?> GetAsync(string scanId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(scanId))
        {
            throw new ArgumentException("Scan ID is required.", nameof(scanId));
        }

        var scans = await scanResultRepository.ListAsync(cancellationToken);
        var scan = scans.FirstOrDefault(item => item.ScanResultId.Equals(scanId, StringComparison.OrdinalIgnoreCase));
        if (scan is null)
        {
            return null;
        }

        var safety = await siteSafetyScanner.ScanAsync(new SiteSafetyScanRequest(BuildSafeScanUrl(scan), BuildSignals(scan)), cancellationToken);
        var feedback = await feedbackAggregationService.GetSummaryAsync(scan.Domain, cancellationToken);
        var review = await FindRelatedReviewAsync(scan, cancellationToken);

        return new AdminScanDetail(
            scan.ScanResultId,
            scan.Domain,
            scan.PageUrlHash,
            "BrowserPluginScan",
            scan.LastCheckedUtc,
            scan.Status,
            safety.Status.ToString(),
            safety.DomainTrustScore,
            safety.PageTrustScore,
            safety.ContentRiskScore,
            safety.FinalHipScore,
            safety.ConfidenceLevel,
            safety.Summary,
            MergeReasons(scan, safety),
            safety.Warnings,
            safety.PositiveSignals,
            safety.NegativeSignals,
            safety.MatchedRules?.Select(ToRuleDetail).ToArray() ?? [],
            safety.ProviderEvidence.Select(ToProviderDetail).ToArray(),
            feedback.RecentFeedbackCount == 0 ? null : ToFeedbackDetail(feedback),
            review is null ? null : ToReviewStatus(review));
    }

    /// <summary>
    /// Builds a scan URL for re-evaluation. Raw stored URLs are only used if a future explicit storage policy supplied one.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <returns>HTTP or HTTPS URL used internally by the scanner.</returns>
    private static string BuildSafeScanUrl(BrowserScanResultRecord scan)
    {
        if (!string.IsNullOrWhiteSpace(scan.StoredPageUrl) &&
            Uri.TryCreate(scan.StoredPageUrl, UriKind.Absolute, out var storedUri) &&
            storedUri.Scheme is "http" or "https")
        {
            return storedUri.ToString();
        }

        return $"https://{scan.Domain}/";
    }

    /// <summary>
    /// Converts stored browser counts and labels into privacy-safe observed signals for current rule evaluation.
    /// </summary>
    /// <param name="scan">Stored browser scan summary.</param>
    /// <returns>Observed signals that do not contain page body text, form values, credentials, or raw private content.</returns>
    private static SiteSafetyObservedSignals BuildSignals(BrowserScanResultRecord scan)
    {
        var metadata = scan.PrivacySafeMetadata;
        var riskTerms = InferRiskTerms(scan).ToArray();
        var downloadCount = ParseMetadataInt(metadata, "downloadCandidates") + ParseMetadataInt(metadata, "downloadCandidateCount");
        var loginForms = ParseMetadataInt(metadata, "loginForms") + ParseMetadataInt(metadata, "loginFormCount");
        var passwordFields = ParseMetadataInt(metadata, "passwordFields") + ParseMetadataInt(metadata, "passwordFieldCount");
        var paymentFields = ParseMetadataInt(metadata, "paymentFields") + ParseMetadataInt(metadata, "paymentFieldCount");
        var obfuscatedLinks = ParseMetadataInt(metadata, "obfuscatedLinks") + ParseMetadataInt(metadata, "obfuscatedLinkCount");

        return new SiteSafetyObservedSignals(
            DownloadLinks: SyntheticDownloadLinks(scan.Domain, downloadCount),
            HasLoginForm: loginForms > 0,
            HasPasswordField: passwordFields > 0,
            HasPaymentField: paymentFields > 0,
            ContainsScamWording: riskTerms.Contains("ScamWording"),
            ContainsUrgencyWording: riskTerms.Contains("UrgencyWording"),
            ContainsImpersonationWording: riskTerms.Contains("ImpersonationWording"),
            KnownPhishingPattern: riskTerms.Contains("KnownPhishingPattern"),
            KnownMalwareIndicator: riskTerms.Contains("KnownMalwareIndicator"),
            KnownAbuseReports: scan.RiskyLinksFound,
            DomainReputationScore: scan.Score,
            PageReputationScore: scan.Score,
            TrustDataAvailable: scan.Score >= 70 || scan.Status.Equals("Trusted", StringComparison.OrdinalIgnoreCase) || scan.Status.Equals("MostlyTrusted", StringComparison.OrdinalIgnoreCase),
            ShortenedLinkCount: Math.Max(0, scan.SuspiciousLinksFound),
            ObfuscatedLinkCount: obfuscatedLinks,
            MatchedRiskTerms: riskTerms);
    }

    /// <summary>
    /// Creates synthetic download URLs only from counts so the rules can evaluate file risk without storing the original link.
    /// </summary>
    /// <param name="domain">Normalized scan domain.</param>
    /// <param name="downloadCount">Privacy-safe count of download-like links.</param>
    /// <returns>Synthetic download links for rule classification.</returns>
    private static IReadOnlyCollection<string> SyntheticDownloadLinks(string domain, int downloadCount) =>
        Enumerable.Range(0, Math.Clamp(downloadCount, 0, 20))
            .Select(index => $"https://{domain}/hip-download-candidate-{index}.exe")
            .ToArray();

    /// <summary>
    /// Infers privacy-safe risk labels from stored reason text and status labels.
    /// </summary>
    /// <param name="scan">Stored scan summary.</param>
    /// <returns>Risk labels, not raw page content.</returns>
    private static IEnumerable<string> InferRiskTerms(BrowserScanResultRecord scan)
    {
        var combined = string.Join(' ', scan.Reasons.Append(scan.RiskLevel).Append(scan.Status));
        if (combined.Contains("phishing", StringComparison.OrdinalIgnoreCase))
        {
            yield return "KnownPhishingPattern";
        }

        if (combined.Contains("malware", StringComparison.OrdinalIgnoreCase))
        {
            yield return "KnownMalwareIndicator";
        }

        if (combined.Contains("scam", StringComparison.OrdinalIgnoreCase))
        {
            yield return "ScamWording";
        }

        if (combined.Contains("urgent", StringComparison.OrdinalIgnoreCase) ||
            combined.Contains("limited time", StringComparison.OrdinalIgnoreCase))
        {
            yield return "UrgencyWording";
        }

        if (combined.Contains("impersonat", StringComparison.OrdinalIgnoreCase))
        {
            yield return "ImpersonationWording";
        }
    }

    /// <summary>
    /// Parses a non-negative integer from optional privacy-safe scan metadata.
    /// </summary>
    /// <param name="metadata">Metadata dictionary.</param>
    /// <param name="key">Key to read.</param>
    /// <returns>Parsed count or zero.</returns>
    private static int ParseMetadataInt(IReadOnlyDictionary<string, string> metadata, string key) =>
        metadata.TryGetValue(key, out var value) && int.TryParse(value, out var parsed)
            ? Math.Max(0, parsed)
            : 0;

    /// <summary>
    /// Keeps the stored browser reason first, then appends current rule reasons.
    /// </summary>
    /// <param name="scan">Stored scan summary.</param>
    /// <param name="safety">Current Site Safety evaluation.</param>
    /// <returns>Distinct reason list.</returns>
    private static IReadOnlyCollection<string> MergeReasons(BrowserScanResultRecord scan, SiteSafetyScanResult safety) =>
        scan.Reasons.Concat(safety.Reasons)
            .Where(reason => !string.IsNullOrWhiteSpace(reason))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>
    /// Converts a matched rule into a display model without exposing raw evidence.
    /// </summary>
    /// <param name="rule">Matched rule.</param>
    /// <returns>Admin rule detail.</returns>
    private static AdminScanMatchedRuleDetail ToRuleDetail(SiteSafetyRuleResult rule) =>
        new(
            rule.RuleId,
            rule.RuleName,
            rule.Source.ToString(),
            rule.Severity.ToString(),
            rule.IsSimulationOnly ? "Simulation" : "Enforced",
            rule.CollectionType.ToString(),
            rule.Reason,
            rule.Warning,
            rule.RiskImpact,
            rule.TrustImpact,
            rule.StatusOverride?.ToString());

    /// <summary>
    /// Summarizes provider evidence across its normalized items.
    /// </summary>
    /// <param name="evidence">Provider evidence.</param>
    /// <returns>Admin evidence detail.</returns>
    private static AdminScanProviderEvidenceDetail ToProviderDetail(SiteSafetyEvidence evidence)
    {
        var items = evidence.EvidenceItems.ToArray();
        var quality = items.Length == 0
            ? "Unknown"
            : items.Select(item => item.EvidenceQuality.ToString()).Distinct().First();
        var summary = items.Select(item => item.Summary).FirstOrDefault(summary => !string.IsNullOrWhiteSpace(summary))
            ?? evidence.Errors.FirstOrDefault()
            ?? "Provider returned no score-changing evidence.";

        return new AdminScanProviderEvidenceDetail(
            evidence.ProviderName,
            evidence.ProviderType.ToString(),
            evidence.Confidence,
            quality,
            summary,
            items.Select(item => item.RiskImpact).DefaultIfEmpty(0).Max(),
            items.Select(item => item.TrustImpact).DefaultIfEmpty(0).Max(),
            evidence.Errors,
            evidence.CheckedAtUtc,
            evidence.ExpiresAtUtc);
    }

    /// <summary>
    /// Converts weighted feedback into read-only admin evidence while avoiding voting language.
    /// </summary>
    /// <param name="summary">Weighted feedback summary.</param>
    /// <returns>Feedback detail.</returns>
    private static AdminScanFeedbackEvidenceDetail ToFeedbackDetail(WeightedFeedbackSummary summary) =>
        new(
            summary.LooksSafeWeight,
            summary.LooksSuspiciousWeight,
            summary.ReportIssueWeight,
            $"{summary.RecentFeedbackCount} recent weighted feedback signal(s); {summary.RepeatedReporterCount} repeated reporter signal(s).",
            summary.ConfidenceImpact,
            summary.RecommendedReview,
            summary.Explanations);

    /// <summary>
    /// Finds the most relevant review queue item for the stored scan by scan ID, URL hash, or domain.
    /// </summary>
    /// <param name="scan">Stored browser scan.</param>
    /// <param name="cancellationToken">Token used to cancel repository work.</param>
    /// <returns>Related review item or null.</returns>
    private async Task<AdminReviewQueueItem?> FindRelatedReviewAsync(BrowserScanResultRecord scan, CancellationToken cancellationToken)
    {
        var reviews = await reviewQueueRepository.ListAsync(cancellationToken);
        return reviews
            .Where(item => item.RelatedScanId?.Equals(scan.ScanResultId, StringComparison.OrdinalIgnoreCase) == true ||
                           item.UrlHash?.Equals(scan.PageUrlHash, StringComparison.OrdinalIgnoreCase) == true ||
                           item.Domain.Equals(scan.Domain, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.UpdatedAtUtc)
            .FirstOrDefault();
    }

    /// <summary>
    /// Converts review queue state into a compact admin detail model.
    /// </summary>
    /// <param name="item">Review queue item.</param>
    /// <returns>Review status detail.</returns>
    private static AdminScanReviewStatusDetail ToReviewStatus(AdminReviewQueueItem item) =>
        new(
            item.ReviewId,
            item.Status.ToString(),
            item.Severity.ToString(),
            item.Source.ToString(),
            item.Summary,
            item.Decision?.ToString(),
            item.DecisionReason);
}
