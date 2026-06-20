using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using HIP.Application.Security;
using HIP.Application.SiteSafety;
using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

/// <summary>
/// User-facing feedback type used by HIP clients. This is weighted trust feedback, not voting.
/// </summary>
public enum HipFeedbackType
{
    /// <summary>
    /// The reporter believes the site looks safe, but HIP still treats this as weak evidence.
    /// </summary>
    LooksSafe,

    /// <summary>
    /// The reporter believes the site looks suspicious, but HIP still requires corroborating evidence.
    /// </summary>
    LooksSuspicious,

    /// <summary>
    /// The reporter is submitting an issue signal that should usually create a review signal.
    /// </summary>
    ReportIssue
}

/// <summary>
/// Privacy-safe reason labels that explain feedback without sending raw page text.
/// </summary>
public enum HipFeedbackReasonCode
{
    /// <summary>
    /// Scam, phishing, or social-engineering concern.
    /// </summary>
    ScamOrPhishing,

    /// <summary>
    /// Login surface appears fake or suspicious.
    /// </summary>
    FakeLogin,

    /// <summary>
    /// Download appears suspicious.
    /// </summary>
    SuspiciousDownload,

    /// <summary>
    /// Redirect behavior appears suspicious.
    /// </summary>
    BadRedirect,

    /// <summary>
    /// Content appears misleading without storing the raw content.
    /// </summary>
    MisleadingContent,

    /// <summary>
    /// Reporter believes HIP flagged something safe.
    /// </summary>
    FalsePositive,

    /// <summary>
    /// General feedback label.
    /// </summary>
    Other
}

/// <summary>
/// HIP client or surface that submitted feedback.
/// </summary>
public enum HipFeedbackSource
{
    /// <summary>
    /// Browser plugin popup.
    /// </summary>
    BrowserPluginPopup,

    /// <summary>
    /// Browser plugin injected banner.
    /// </summary>
    BrowserPluginBanner,

    /// <summary>
    /// Admin portal.
    /// </summary>
    AdminPortal,

    /// <summary>
    /// Direct API client.
    /// </summary>
    Api
}

/// <summary>
/// Privacy-safe weighted feedback submitted by a HIP client.
/// </summary>
/// <param name="Domain">Normalized or normalizable domain.</param>
/// <param name="FeedbackType">Feedback type. This must never be treated as a raw vote.</param>
/// <param name="Source">Client or portal source.</param>
/// <param name="ReporterTrustLevel">Reporter trust level used for conservative weighting.</param>
/// <param name="SubmittedAtUtc">UTC submission time.</param>
/// <param name="PageUrlHash">Optional page URL hash. Full raw URLs are intentionally not required.</param>
/// <param name="ReporterHash">Optional browser, device, or account hash used only for abuse controls.</param>
/// <param name="PluginVersion">Optional plugin version for debugging stale clients.</param>
/// <param name="ReasonCode">Optional privacy-safe reason code.</param>
public sealed record WeightedFeedbackSubmission(
    string Domain,
    HipFeedbackType FeedbackType,
    HipFeedbackSource Source,
    ReporterTrustLevel ReporterTrustLevel,
    DateTimeOffset SubmittedAtUtc,
    string? PageUrlHash = null,
    string? ReporterHash = null,
    string? PluginVersion = null,
    HipFeedbackReasonCode? ReasonCode = null);

/// <summary>
/// Aggregated feedback totals used as weak site-safety evidence.
/// </summary>
/// <param name="Domain">Normalized domain.</param>
/// <param name="LooksSafeWeight">Total weighted safe feedback.</param>
/// <param name="LooksSuspiciousWeight">Total weighted suspicious feedback.</param>
/// <param name="ReportIssueWeight">Total weighted report-issue feedback.</param>
/// <param name="RecentFeedbackCount">Feedback count in the aggregation window.</param>
/// <param name="RepeatedReporterCount">Number of repeated reports from the same reporter hash.</param>
/// <param name="SuspiciousFeedbackPattern">Whether feedback itself looks spammy or abusive.</param>
/// <param name="ConflictingFeedbackSpike">Whether safe and suspicious feedback conflict.</param>
/// <param name="ConfidenceImpact">0-100 confidence penalty suggested by feedback conflict or abuse patterns.</param>
/// <param name="RecommendedReview">Whether an admin review signal should be created.</param>
/// <param name="Explanations">Plain-English explanations that avoid voting language.</param>
public sealed record WeightedFeedbackSummary(
    string Domain,
    int LooksSafeWeight,
    int LooksSuspiciousWeight,
    int ReportIssueWeight,
    int RecentFeedbackCount,
    int RepeatedReporterCount,
    bool SuspiciousFeedbackPattern,
    bool ConflictingFeedbackSpike,
    int ConfidenceImpact,
    bool RecommendedReview,
    IReadOnlyCollection<string> Explanations);

/// <summary>
/// Stores privacy-safe weighted feedback submissions.
/// </summary>
public interface IWeightedFeedbackRepository
{
    /// <summary>
    /// Saves a privacy-safe feedback submission.
    /// </summary>
    /// <param name="submission">Feedback submission.</param>
    /// <param name="cancellationToken">Token used to cancel repository work.</param>
    /// <returns>Completed task.</returns>
    Task SaveAsync(WeightedFeedbackSubmission submission, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent feedback for one normalized domain.
    /// </summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="sinceUtc">Lower UTC bound for feedback aggregation.</param>
    /// <param name="cancellationToken">Token used to cancel repository work.</param>
    /// <returns>Recent submissions.</returns>
    Task<IReadOnlyCollection<WeightedFeedbackSubmission>> ListRecentAsync(string domain, DateTimeOffset sinceUtc, CancellationToken cancellationToken);

    /// <summary>
    /// Lists all privacy-safe feedback submissions for administrative summaries.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel repository work.</param>
    /// <returns>All stored feedback submissions.</returns>
    Task<IReadOnlyCollection<WeightedFeedbackSubmission>> ListAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Development in-memory weighted feedback repository.
/// </summary>
public sealed class InMemoryWeightedFeedbackRepository : IWeightedFeedbackRepository
{
    private readonly ConcurrentDictionary<string, List<WeightedFeedbackSubmission>> submissions = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task SaveAsync(WeightedFeedbackSubmission submission, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var list = submissions.GetOrAdd(submission.Domain, _ => []);
        lock (list)
        {
            list.Add(submission);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<WeightedFeedbackSubmission>> ListRecentAsync(string domain, DateTimeOffset sinceUtc, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!submissions.TryGetValue(domain, out var list))
        {
            return Task.FromResult<IReadOnlyCollection<WeightedFeedbackSubmission>>([]);
        }

        lock (list)
        {
            return Task.FromResult<IReadOnlyCollection<WeightedFeedbackSubmission>>(
                list.Where(item => item.SubmittedAtUtc >= sinceUtc)
                    .OrderBy(item => item.SubmittedAtUtc)
                    .ToArray());
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<WeightedFeedbackSubmission>> ListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var all = submissions.Values
            .SelectMany(list =>
            {
                lock (list)
                {
                    return list.ToArray();
                }
            })
            .OrderByDescending(item => item.SubmittedAtUtc)
            .ToArray();

        return Task.FromResult<IReadOnlyCollection<WeightedFeedbackSubmission>>(all);
    }
}

/// <summary>
/// Aggregates weighted feedback into privacy-safe scoring evidence.
/// </summary>
public interface IWeightedFeedbackAggregationService
{
    /// <summary>
    /// Saves feedback after validation and normalization.
    /// </summary>
    /// <param name="submission">Privacy-safe feedback submission.</param>
    /// <param name="cancellationToken">Token used to cancel service work.</param>
    /// <returns>Aggregate summary after storing the submission.</returns>
    Task<WeightedFeedbackSummary> SubmitAsync(WeightedFeedbackSubmission submission, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the aggregate summary for one domain.
    /// </summary>
    /// <param name="domain">Domain to aggregate.</param>
    /// <param name="cancellationToken">Token used to cancel service work.</param>
    /// <returns>Weighted feedback summary.</returns>
    Task<WeightedFeedbackSummary> GetSummaryAsync(string domain, CancellationToken cancellationToken);
}

/// <summary>
/// Conservative feedback aggregator that treats feedback as weak evidence, not proof.
/// </summary>
public sealed partial class WeightedFeedbackAggregationService(
    IWeightedFeedbackRepository repository,
    IFeedbackWeightingPolicy feedbackWeightingPolicy) : IWeightedFeedbackAggregationService
{
    private static readonly TimeSpan AggregationWindow = TimeSpan.FromDays(14);

    /// <summary>
    /// Creates an aggregator with the default feedback weighting policy for tests and older callers.
    /// </summary>
    /// <param name="repository">Repository that stores privacy-safe feedback submissions.</param>
    public WeightedFeedbackAggregationService(IWeightedFeedbackRepository repository)
        : this(repository, new DefaultFeedbackWeightingPolicy())
    {
    }

    /// <inheritdoc />
    public async Task<WeightedFeedbackSummary> SubmitAsync(WeightedFeedbackSubmission submission, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        var normalized = NormalizeAndValidate(submission);
        await repository.SaveAsync(normalized, cancellationToken);
        return await GetSummaryAsync(normalized.Domain, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<WeightedFeedbackSummary> GetSummaryAsync(string domain, CancellationToken cancellationToken)
    {
        var normalizedDomain = NormalizeDomain(domain);
        var recent = await repository.ListRecentAsync(normalizedDomain, DateTimeOffset.UtcNow.Subtract(AggregationWindow), cancellationToken);
        return BuildSummary(normalizedDomain, recent);
    }

    /// <summary>
    /// Converts an existing reputation feedback request into weighted feedback for scoring evidence.
    /// </summary>
    /// <param name="feedback">Existing reputation feedback request.</param>
    /// <returns>Weighted feedback submission.</returns>
    public static WeightedFeedbackSubmission FromReputationFeedback(ReputationFeedbackRequest feedback)
    {
        var feedbackType = feedback.EventType switch
        {
            ReputationEventType.PositiveReport or ReputationEventType.FalsePositiveCorrection => HipFeedbackType.LooksSafe,
            ReputationEventType.SuspiciousReport => HipFeedbackType.LooksSuspicious,
            _ => HipFeedbackType.ReportIssue
        };
        var source = feedback.Platform.Contains("banner", StringComparison.OrdinalIgnoreCase)
            ? HipFeedbackSource.BrowserPluginBanner
            : feedback.Platform.Contains("admin", StringComparison.OrdinalIgnoreCase)
                ? HipFeedbackSource.AdminPortal
                : feedback.Platform.Contains("browser", StringComparison.OrdinalIgnoreCase)
                    ? HipFeedbackSource.BrowserPluginPopup
                    : HipFeedbackSource.Api;

        return new WeightedFeedbackSubmission(
            feedback.TargetId,
            feedbackType,
            source,
            feedback.ReporterTrustLevel,
            DateTimeOffset.UtcNow,
            feedback.UrlHash,
            ReporterHash: null,
            PluginVersion: null,
            ReasonCode: InferReasonCode(feedback.Reason));
    }

    /// <summary>
    /// Builds a summary from recent submissions.
    /// </summary>
    private WeightedFeedbackSummary BuildSummary(string domain, IReadOnlyCollection<WeightedFeedbackSubmission> recent)
    {
        var looksSafeWeight = TotalWeight(recent, HipFeedbackType.LooksSafe);
        var suspiciousWeight = TotalWeight(recent, HipFeedbackType.LooksSuspicious);
        var issueWeight = TotalWeight(recent, HipFeedbackType.ReportIssue);
        var repeatedReporterCount = recent.Where(item => !string.IsNullOrWhiteSpace(item.ReporterHash))
            .GroupBy(item => item.ReporterHash, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Sum(group => group.Count() - 1);
        var lowTrustSuspiciousCount = recent.Count(item =>
            item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue &&
            item.ReporterTrustLevel is ReporterTrustLevel.Anonymous or ReporterTrustLevel.KnownFalseReporter);
        var suspiciousFeedbackPattern = repeatedReporterCount >= 3 || lowTrustSuspiciousCount >= 8;
        var conflicting = looksSafeWeight >= 6 && suspiciousWeight + issueWeight >= 6;
        var trustedRiskReport = recent.Any(item =>
            item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue &&
            item.ReporterTrustLevel is ReporterTrustLevel.Trusted or ReporterTrustLevel.Moderator or ReporterTrustLevel.Admin);
        var adminIssue = recent.Any(item => item.FeedbackType == HipFeedbackType.ReportIssue && item.ReporterTrustLevel == ReporterTrustLevel.Admin);
        var manySuspiciousQuickly = recent.Count(item => item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue) >= 5;
        var manyLooksSafe = recent.Count(item => item.FeedbackType == HipFeedbackType.LooksSafe) >= 5;
        var confidenceImpact = Math.Clamp((conflicting ? 25 : 0) + (suspiciousFeedbackPattern ? 20 : 0), 0, 100);
        var review = manySuspiciousQuickly || conflicting || trustedRiskReport || adminIssue || manyLooksSafe || suspiciousFeedbackPattern;

        return new WeightedFeedbackSummary(
            domain,
            looksSafeWeight,
            suspiciousWeight,
            issueWeight,
            recent.Count,
            repeatedReporterCount,
            suspiciousFeedbackPattern,
            conflicting,
            confidenceImpact,
            review,
            BuildExplanations(looksSafeWeight, suspiciousWeight, issueWeight, conflicting, suspiciousFeedbackPattern, review));
    }

    /// <summary>
    /// Builds plain-English explanations that avoid voting language.
    /// </summary>
    private static IReadOnlyCollection<string> BuildExplanations(int looksSafeWeight, int suspiciousWeight, int issueWeight, bool conflicting, bool suspiciousPattern, bool review)
    {
        var explanations = new List<string>();
        if (looksSafeWeight > 0)
        {
            explanations.Add("Some users reported this site as looking safe, but HIP treats feedback as weak supporting evidence.");
        }

        if (suspiciousWeight > 0 || issueWeight > 0)
        {
            explanations.Add("Some users reported this site as suspicious, but HIP has not confirmed a threat from feedback alone.");
        }

        if (conflicting)
        {
            explanations.Add("Recent feedback is conflicting, so HIP lowered confidence and recommends review.");
        }

        if (suspiciousPattern)
        {
            explanations.Add("Recent feedback patterns may be repetitive or low-quality, so HIP recommends review instead of trusting the reports directly.");
        }

        if (review && !conflicting && !suspiciousPattern)
        {
            explanations.Add("Feedback volume or reporter trust level recommends admin review.");
        }

        return explanations.Count == 0
            ? ["HIP has not received recent privacy-safe feedback for this domain."]
            : explanations;
    }

    /// <summary>
    /// Totals feedback weight by type.
    /// </summary>
    private int TotalWeight(IEnumerable<WeightedFeedbackSubmission> submissions, HipFeedbackType feedbackType) =>
        submissions.Where(item => item.FeedbackType == feedbackType)
            .Sum(item => feedbackWeightingPolicy.CalculateWeight(item.FeedbackType, item.ReporterTrustLevel, item.Source));

    /// <summary>
    /// Validates and normalizes a submission without accepting raw private content.
    /// </summary>
    private static WeightedFeedbackSubmission NormalizeAndValidate(WeightedFeedbackSubmission submission)
    {
        var domain = NormalizeDomain(submission.Domain);
        RejectPrivateOrOversized(submission.PageUrlHash, nameof(submission.PageUrlHash));
        RejectPrivateOrOversized(submission.ReporterHash, nameof(submission.ReporterHash));
        RejectPrivateOrOversized(submission.PluginVersion, nameof(submission.PluginVersion));

        return submission with
        {
            Domain = domain,
            SubmittedAtUtc = submission.SubmittedAtUtc == default ? DateTimeOffset.UtcNow : submission.SubmittedAtUtc
        };
    }

    /// <summary>
    /// Normalizes and validates a public domain label.
    /// </summary>
    private static string NormalizeDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Feedback domain is required.", nameof(domain));
        }

        var normalized = domain.Trim().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();
        if (!DomainPattern().IsMatch(normalized))
        {
            throw new ArgumentException("Feedback domain is invalid.", nameof(domain));
        }

        return normalized;
    }

    /// <summary>
    /// Rejects oversized or obviously private strings while allowing hashes and short labels.
    /// </summary>
    private static void RejectPrivateOrOversized(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (value.Length > 128 ||
            value.Contains("password", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("token=", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("private message", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("form value", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"{fieldName} contains data HIP does not accept in feedback.", fieldName);
        }
    }

    /// <summary>
    /// Infers a privacy-safe reason code from an existing plain-English reputation reason.
    /// </summary>
    private static HipFeedbackReasonCode InferReasonCode(string reason)
    {
        if (reason.Contains("login", StringComparison.OrdinalIgnoreCase))
        {
            return HipFeedbackReasonCode.FakeLogin;
        }

        if (reason.Contains("download", StringComparison.OrdinalIgnoreCase))
        {
            return HipFeedbackReasonCode.SuspiciousDownload;
        }

        if (reason.Contains("redirect", StringComparison.OrdinalIgnoreCase))
        {
            return HipFeedbackReasonCode.BadRedirect;
        }

        if (reason.Contains("false positive", StringComparison.OrdinalIgnoreCase))
        {
            return HipFeedbackReasonCode.FalsePositive;
        }

        return reason.Contains("phish", StringComparison.OrdinalIgnoreCase) || reason.Contains("scam", StringComparison.OrdinalIgnoreCase)
            ? HipFeedbackReasonCode.ScamOrPhishing
            : HipFeedbackReasonCode.Other;
    }

    /// <summary>
    /// Domain validation pattern that avoids accepting URLs or arbitrary text.
    /// </summary>
    [GeneratedRegex(@"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DomainPattern();
}

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
