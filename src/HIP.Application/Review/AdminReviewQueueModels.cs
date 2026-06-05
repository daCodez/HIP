using FluentValidation;
using HIP.Application.Reputation;
using HIP.Application.SiteSafety;
using HIP.Domain.Audit;
using HIP.Domain.Review;

namespace HIP.Application.Review;

/// <summary>
/// Target type for the admin review queue foundation.
/// </summary>
public enum AdminReviewTargetType
{
    Domain,
    Url,
    Website,
    Rule,
    Feedback,
    ProviderEvidence,
    Scan
}

/// <summary>
/// Status for an admin review queue item.
/// </summary>
public enum AdminReviewStatus
{
    Open,
    InReview,
    Resolved,
    Dismissed,
    Escalated
}

/// <summary>
/// Severity for an admin review queue item.
/// </summary>
public enum AdminReviewSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Source that created an admin review item.
/// </summary>
public enum AdminReviewSource
{
    SiteSafetyScan,
    UserFeedback,
    AdminRule,
    ExternalProvider,
    HipHistory,
    System
}

/// <summary>
/// Admin review decision. MVP decisions are recorded as evidence only and do not silently override scoring.
/// </summary>
public enum AdminReviewDecision
{
    ConfirmSafe,
    ConfirmSuspicious,
    ConfirmHighRisk,
    ConfirmDangerous,
    FalsePositive,
    NeedsMoreData,
    NoAction
}

/// <summary>
/// Privacy-safe admin review item for uncertain, risky, conflicting, or important HIP cases.
/// </summary>
/// <param name="ReviewId">Stable review item ID.</param>
/// <param name="Domain">Normalized domain.</param>
/// <param name="UrlHash">Optional URL hash. Raw private URLs are not stored.</param>
/// <param name="TargetType">Target scope.</param>
/// <param name="ReviewReason">Machine-readable review reason label.</param>
/// <param name="Severity">Review severity.</param>
/// <param name="Status">Review status.</param>
/// <param name="Source">Review source.</param>
/// <param name="RelatedScanId">Optional related scan ID.</param>
/// <param name="RelatedRuleId">Optional related rule ID.</param>
/// <param name="RelatedFeedbackId">Optional related feedback ID or hash.</param>
/// <param name="CurrentFinalHipScore">Current final HIP score when available.</param>
/// <param name="CurrentStatus">Current status label when available.</param>
/// <param name="ConfidenceLevel">Current confidence label.</param>
/// <param name="Summary">Plain-English privacy-safe summary.</param>
/// <param name="EvidenceSummary">Privacy-safe evidence summary.</param>
/// <param name="CreatedAtUtc">UTC creation time.</param>
/// <param name="UpdatedAtUtc">UTC update time.</param>
/// <param name="AssignedTo">Optional assigned reviewer.</param>
/// <param name="ReviewedBy">Optional reviewer who made a decision.</param>
/// <param name="ReviewedAtUtc">Optional review decision time.</param>
/// <param name="Decision">Optional admin decision.</param>
/// <param name="DecisionReason">Optional privacy-safe decision reason.</param>
public sealed record AdminReviewQueueItem(
    string ReviewId,
    string Domain,
    string? UrlHash,
    AdminReviewTargetType TargetType,
    string ReviewReason,
    AdminReviewSeverity Severity,
    AdminReviewStatus Status,
    AdminReviewSource Source,
    string? RelatedScanId,
    string? RelatedRuleId,
    string? RelatedFeedbackId,
    int? CurrentFinalHipScore,
    string? CurrentStatus,
    string? ConfidenceLevel,
    string Summary,
    string EvidenceSummary,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string? AssignedTo,
    string? ReviewedBy,
    DateTimeOffset? ReviewedAtUtc,
    AdminReviewDecision? Decision,
    string? DecisionReason);

/// <summary>
/// Input used to create or deduplicate an admin review item.
/// </summary>
/// <param name="Domain">Normalized or normalizable domain.</param>
/// <param name="UrlHash">Optional URL hash.</param>
/// <param name="TargetType">Target type.</param>
/// <param name="ReviewReason">Review reason label.</param>
/// <param name="Severity">Review severity.</param>
/// <param name="Source">Review source.</param>
/// <param name="RelatedScanId">Optional related scan ID.</param>
/// <param name="RelatedRuleId">Optional related rule ID.</param>
/// <param name="RelatedFeedbackId">Optional related feedback ID or hash.</param>
/// <param name="CurrentFinalHipScore">Current final HIP score.</param>
/// <param name="CurrentStatus">Current status label.</param>
/// <param name="ConfidenceLevel">Current confidence label.</param>
/// <param name="Summary">Privacy-safe summary.</param>
/// <param name="EvidenceSummary">Privacy-safe evidence summary.</param>
public sealed record AdminReviewSignal(
    string Domain,
    string? UrlHash,
    AdminReviewTargetType TargetType,
    string ReviewReason,
    AdminReviewSeverity Severity,
    AdminReviewSource Source,
    string? RelatedScanId,
    string? RelatedRuleId,
    string? RelatedFeedbackId,
    int? CurrentFinalHipScore,
    string? CurrentStatus,
    string? ConfidenceLevel,
    string Summary,
    string EvidenceSummary);

/// <summary>
/// Records an admin review decision without directly overriding scoring.
/// </summary>
/// <param name="Decision">Decision to record.</param>
/// <param name="DecisionReason">Privacy-safe decision reason.</param>
/// <param name="ReviewedBy">Reviewer ID or hash.</param>
public sealed record AdminReviewDecisionRequest(
    AdminReviewDecision Decision,
    string DecisionReason,
    string ReviewedBy);

/// <summary>
/// Repository for admin review queue items.
/// </summary>
public interface IAdminReviewQueueRepository
{
    /// <summary>
    /// Saves an admin review queue item.
    /// </summary>
    Task SaveAsync(AdminReviewQueueItem item, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a review item by ID.
    /// </summary>
    Task<AdminReviewQueueItem?> GetAsync(string reviewId, CancellationToken cancellationToken);

    /// <summary>
    /// Lists review items.
    /// </summary>
    Task<IReadOnlyCollection<AdminReviewQueueItem>> ListAsync(CancellationToken cancellationToken);
}

/// <summary>
/// In-memory admin review queue repository for tests and lightweight development hosts.
/// </summary>
public sealed class InMemoryAdminReviewQueueRepository : IAdminReviewQueueRepository
{
    private readonly Dictionary<string, AdminReviewQueueItem> items = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    /// <inheritdoc />
    public Task SaveAsync(AdminReviewQueueItem item, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            items[item.ReviewId] = item;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<AdminReviewQueueItem?> GetAsync(string reviewId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult(items.GetValueOrDefault(reviewId));
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyCollection<AdminReviewQueueItem>> ListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<AdminReviewQueueItem>>(items.Values.OrderByDescending(item => item.CreatedAtUtc).ToArray());
        }
    }
}

/// <summary>
/// Service contract for the admin review queue foundation.
/// </summary>
public interface IAdminReviewQueueService
{
    /// <summary>
    /// Creates or reuses an open review item for a signal.
    /// </summary>
    Task<AdminReviewQueueItem> CreateSignalAsync(AdminReviewSignal signal, CancellationToken cancellationToken);

    /// <summary>
    /// Lists review items.
    /// </summary>
    Task<IReadOnlyCollection<AdminReviewQueueItem>> ListAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets a review item by ID.
    /// </summary>
    Task<AdminReviewQueueItem?> GetAsync(string reviewId, CancellationToken cancellationToken);

    /// <summary>
    /// Assigns a review item.
    /// </summary>
    Task<AdminReviewQueueItem> AssignAsync(string reviewId, string assignedTo, string actorId, CancellationToken cancellationToken);

    /// <summary>
    /// Records a review decision.
    /// </summary>
    Task<AdminReviewQueueItem> RecordDecisionAsync(string reviewId, AdminReviewDecisionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Dismisses a review item without deleting its evidence summary.
    /// </summary>
    Task<AdminReviewQueueItem> DismissAsync(string reviewId, string actorId, string reason, CancellationToken cancellationToken);

    /// <summary>
    /// Creates review signals from a completed site safety scan.
    /// </summary>
    Task<IReadOnlyCollection<AdminReviewQueueItem>> CreateSignalsFromScanAsync(SiteSafetyScanResult scanResult, CancellationToken cancellationToken);

    /// <summary>
    /// Creates review signals from weighted feedback aggregation.
    /// </summary>
    Task<IReadOnlyCollection<AdminReviewQueueItem>> CreateSignalsFromFeedbackAsync(WeightedFeedbackSummary summary, CancellationToken cancellationToken);
}

/// <summary>
/// Validates admin review items and blocks obvious private content.
/// </summary>
public sealed class AdminReviewQueueItemValidator : AbstractValidator<AdminReviewQueueItem>
{
    /// <summary>
    /// Creates validation rules for privacy-safe admin review items.
    /// </summary>
    public AdminReviewQueueItemValidator()
    {
        RuleFor(item => item.ReviewId).NotEmpty();
        RuleFor(item => item.Domain).NotEmpty();
        RuleFor(item => item.TargetType).IsInEnum();
        RuleFor(item => item.ReviewReason).NotEmpty();
        RuleFor(item => item.Severity).IsInEnum();
        RuleFor(item => item.Status).IsInEnum();
        RuleFor(item => item.Source).IsInEnum();
        RuleFor(item => item.Summary).NotEmpty().Must(NotContainPrivateContent);
        RuleFor(item => item.EvidenceSummary).NotEmpty().Must(NotContainPrivateContent);
        RuleFor(item => item.DecisionReason).Must(value => value is null || NotContainPrivateContent(value));
    }

    /// <summary>
    /// Detects text that looks like raw private content and should not enter review records.
    /// </summary>
    private static bool NotContainPrivateContent(string value) =>
        !value.Contains("page text", StringComparison.OrdinalIgnoreCase) &&
        !value.Contains("form value", StringComparison.OrdinalIgnoreCase) &&
        !value.Contains("password", StringComparison.OrdinalIgnoreCase) &&
        !value.Contains("token=", StringComparison.OrdinalIgnoreCase) &&
        !value.Contains("cookie", StringComparison.OrdinalIgnoreCase) &&
        !value.Contains("private message", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Admin review queue MVP service.
/// </summary>
public sealed class AdminReviewQueueService(
    IAdminReviewQueueRepository repository,
    IValidator<AdminReviewQueueItem> validator,
    IAuditLogService auditLogService) : IAdminReviewQueueService
{
    /// <inheritdoc />
    public async Task<AdminReviewQueueItem> CreateSignalAsync(AdminReviewSignal signal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signal);
        var now = DateTimeOffset.UtcNow;
        var normalizedDomain = NormalizeDomain(signal.Domain);
        var existing = (await repository.ListAsync(cancellationToken))
            .FirstOrDefault(item =>
                item.Domain.Equals(normalizedDomain, StringComparison.OrdinalIgnoreCase) &&
                item.UrlHash == signal.UrlHash &&
                item.ReviewReason.Equals(signal.ReviewReason, StringComparison.OrdinalIgnoreCase) &&
                item.Status is AdminReviewStatus.Open or AdminReviewStatus.InReview or AdminReviewStatus.Escalated);

        if (existing is not null)
        {
            return existing;
        }

        var item = new AdminReviewQueueItem(
            $"admin-review-{Guid.NewGuid():N}",
            normalizedDomain,
            signal.UrlHash,
            signal.TargetType,
            signal.ReviewReason,
            signal.Severity,
            AdminReviewStatus.Open,
            signal.Source,
            signal.RelatedScanId,
            signal.RelatedRuleId,
            signal.RelatedFeedbackId,
            signal.CurrentFinalHipScore,
            signal.CurrentStatus,
            signal.ConfidenceLevel,
            SanitizeOrFallback(signal.Summary, "Review signal was created from privacy-safe HIP evidence."),
            SanitizeOrFallback(signal.EvidenceSummary, signal.Summary),
            now,
            now,
            null,
            null,
            null,
            null,
            null);

        validator.ValidateAndThrow(item);
        await repository.SaveAsync(item, cancellationToken);
        auditLogService.Write("system", "Admin review item created", TargetType.Domain, item.Domain, item.Summary, AuditSeverity.Medium);
        return item;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AdminReviewQueueItem>> ListAsync(CancellationToken cancellationToken) =>
        (await repository.ListAsync(cancellationToken)).OrderByDescending(item => item.CreatedAtUtc).ToArray();

    /// <inheritdoc />
    public Task<AdminReviewQueueItem?> GetAsync(string reviewId, CancellationToken cancellationToken) =>
        repository.GetAsync(reviewId, cancellationToken);

    /// <inheritdoc />
    public async Task<AdminReviewQueueItem> AssignAsync(string reviewId, string assignedTo, string actorId, CancellationToken cancellationToken)
    {
        var item = await RequiredAsync(reviewId, cancellationToken);
        var updated = item with
        {
            AssignedTo = assignedTo,
            Status = AdminReviewStatus.InReview,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        validator.ValidateAndThrow(updated);
        await repository.SaveAsync(updated, cancellationToken);
        auditLogService.Write(actorId, "Admin review item assigned", TargetType.Domain, updated.Domain, $"Assigned to {assignedTo}.", AuditSeverity.Low);
        return updated;
    }

    /// <inheritdoc />
    public async Task<AdminReviewQueueItem> RecordDecisionAsync(string reviewId, AdminReviewDecisionRequest request, CancellationToken cancellationToken)
    {
        var item = await RequiredAsync(reviewId, cancellationToken);
        var updated = item with
        {
            Status = request.Decision == AdminReviewDecision.NeedsMoreData ? AdminReviewStatus.Escalated : AdminReviewStatus.Resolved,
            ReviewedBy = request.ReviewedBy,
            ReviewedAtUtc = DateTimeOffset.UtcNow,
            Decision = request.Decision,
            DecisionReason = Sanitize(request.DecisionReason),
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        validator.ValidateAndThrow(updated);
        await repository.SaveAsync(updated, cancellationToken);
        auditLogService.Write(request.ReviewedBy, "Admin review decision recorded", TargetType.Domain, updated.Domain, updated.DecisionReason ?? "Decision recorded.", AuditSeverity.High);
        return updated;
    }

    /// <inheritdoc />
    public async Task<AdminReviewQueueItem> DismissAsync(string reviewId, string actorId, string reason, CancellationToken cancellationToken)
    {
        var item = await RequiredAsync(reviewId, cancellationToken);
        var updated = item with
        {
            Status = AdminReviewStatus.Dismissed,
            ReviewedBy = actorId,
            ReviewedAtUtc = DateTimeOffset.UtcNow,
            Decision = AdminReviewDecision.NoAction,
            DecisionReason = Sanitize(reason),
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        validator.ValidateAndThrow(updated);
        await repository.SaveAsync(updated, cancellationToken);
        auditLogService.Write(actorId, "Admin review item dismissed", TargetType.Domain, updated.Domain, updated.DecisionReason ?? "Dismissed.", AuditSeverity.Medium);
        return updated;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AdminReviewQueueItem>> CreateSignalsFromScanAsync(SiteSafetyScanResult scanResult, CancellationToken cancellationToken)
    {
        var signals = BuildScanSignals(scanResult);
        var items = new List<AdminReviewQueueItem>();
        foreach (var signal in signals)
        {
            items.Add(await CreateSignalAsync(signal, cancellationToken));
        }

        return items;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<AdminReviewQueueItem>> CreateSignalsFromFeedbackAsync(WeightedFeedbackSummary summary, CancellationToken cancellationToken)
    {
        if (!summary.RecommendedReview)
        {
            return [];
        }

        var severity = summary.SuspiciousFeedbackPattern || summary.ConflictingFeedbackSpike ? AdminReviewSeverity.Medium : AdminReviewSeverity.Low;
        var item = await CreateSignalAsync(new AdminReviewSignal(
            summary.Domain,
            null,
            AdminReviewTargetType.Feedback,
            summary.ConflictingFeedbackSpike ? "ConflictingFeedbackReports" : "WeightedFeedbackReview",
            severity,
            AdminReviewSource.UserFeedback,
            null,
            null,
            null,
            null,
            null,
            summary.ConfidenceImpact > 0 ? "Low" : "Medium",
            "Weighted feedback recommends admin review.",
            string.Join(" ", summary.Explanations)), cancellationToken);

        return [item];
    }

    /// <summary>
    /// Builds review signals from scan result conditions.
    /// </summary>
    private static IReadOnlyCollection<AdminReviewSignal> BuildScanSignals(SiteSafetyScanResult result)
    {
        var signals = new List<AdminReviewSignal>();
        var baseSignal = new Func<string, AdminReviewSeverity, AdminReviewSource, string, string, AdminReviewSignal>((reason, severity, source, summary, evidence) =>
            new AdminReviewSignal(result.Domain, result.ProviderEvidence.FirstOrDefault()?.UrlHash, AdminReviewTargetType.Url, reason, severity, source, result.ScanId, null, null, result.FinalHipScore, result.Status.ToString(), result.ConfidenceLevel, summary, evidence));

        if (result.Status is SiteSafetyScanStatus.HighRisk or SiteSafetyScanStatus.Dangerous && result.ConfidenceLevel.Equals("Low", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(baseSignal("HighRiskLowConfidence", AdminReviewSeverity.High, AdminReviewSource.SiteSafetyScan, "High-risk scan has low confidence.", result.Summary));
        }

        if (result.MatchedRules?.Any(rule => rule.RuleId.Equals("external-conflict", StringComparison.OrdinalIgnoreCase)) == true)
        {
            signals.Add(baseSignal("ConflictingProviderEvidence", AdminReviewSeverity.High, AdminReviewSource.ExternalProvider, "External provider evidence conflicts.", string.Join(" ", result.Warnings)));
        }

        if (result.Status is SiteSafetyScanStatus.LimitedData && (result.FormRiskScore >= 45 || result.Warnings.Any(warning => warning.Contains("login fields", StringComparison.OrdinalIgnoreCase))))
        {
            signals.Add(baseSignal("UnknownDomainLoginForm", AdminReviewSeverity.Medium, AdminReviewSource.SiteSafetyScan, "Unknown or limited-data domain contains login fields.", string.Join(" ", result.Warnings)));
        }

        if (result.Status is SiteSafetyScanStatus.LimitedData or SiteSafetyScanStatus.Suspicious && result.Warnings.Any(warning => warning.Contains("payment fields", StringComparison.OrdinalIgnoreCase)))
        {
            signals.Add(baseSignal("UnknownDomainPaymentField", AdminReviewSeverity.High, AdminReviewSource.SiteSafetyScan, "Unknown or limited-data domain contains payment fields.", string.Join(" ", result.Warnings)));
        }

        if (result.DomainTrustScore >= 85 && (result.DownloadRiskScore >= 45 || result.ContentRiskScore < 60 || result.PageTrustScore < 60))
        {
            signals.Add(baseSignal("TrustedDomainRiskyPageContent", AdminReviewSeverity.High, AdminReviewSource.SiteSafetyScan, "Trusted parent domain has risky page or content signals.", string.Join(" ", result.Reasons)));
        }

        if (result.ProviderEvidence.Any(evidence => evidence.Errors.Count > 0) && result.DomainTrustScore >= 80)
        {
            signals.Add(baseSignal("ImportantProviderFailure", AdminReviewSeverity.Medium, AdminReviewSource.ExternalProvider, "Provider failed on an important target.", string.Join(" ", result.ProviderEvidence.SelectMany(evidence => evidence.Errors))));
        }

        return signals;
    }

    /// <summary>
    /// Gets a review item or throws a clear exception.
    /// </summary>
    private async Task<AdminReviewQueueItem> RequiredAsync(string reviewId, CancellationToken cancellationToken) =>
        await repository.GetAsync(reviewId, cancellationToken) ?? throw new ArgumentException("Review item was not found.", nameof(reviewId));

    /// <summary>
    /// Normalizes domains for dedupe and display.
    /// </summary>
    private static string NormalizeDomain(string domain) =>
        string.IsNullOrWhiteSpace(domain)
            ? throw new ArgumentException("Review domain is required.", nameof(domain))
            : domain.Trim().Replace("www.", string.Empty, StringComparison.OrdinalIgnoreCase).ToLowerInvariant();

    /// <summary>
    /// Sanitizes summaries so review records do not store obvious private content.
    /// </summary>
    private static string Sanitize(string value) =>
        value.Contains("page text", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("form value", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("password", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("token=", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("private message", StringComparison.OrdinalIgnoreCase)
            ? "[privacy-safe review summary redacted]"
            : value;

    /// <summary>
    /// Sanitizes a summary and supplies a safe fallback when upstream evidence has no text to display.
    /// </summary>
    private static string SanitizeOrFallback(string value, string fallback) =>
        Sanitize(string.IsNullOrWhiteSpace(value) ? fallback : value);
}
