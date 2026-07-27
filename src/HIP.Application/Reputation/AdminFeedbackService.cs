using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

/// <summary>
/// Provides bounded, privacy-safe administrative views over stored weighted feedback.
/// </summary>
public interface IAdminFeedbackService
{
    Task<AdminFeedbackOverview> GetOverviewAsync(CancellationToken cancellationToken);

    Task<AdminFeedbackDomainDetail?> GetDomainAsync(string domain, CancellationToken cancellationToken);
}

/// <summary>Stored feedback totals and the most recently active domains.</summary>
public sealed record AdminFeedbackOverview(
    int TotalSubmissions,
    int DistinctDomains,
    int LooksSafeCount,
    int LooksSuspiciousCount,
    int ReportIssueCount,
    IReadOnlyCollection<AdminFeedbackDomainRow> Domains);

/// <summary>A privacy-safe per-domain row. Reporter and page hashes are intentionally excluded.</summary>
public sealed record AdminFeedbackDomainRow(
    string Domain,
    int SubmissionCount,
    int LooksSafeCount,
    int LooksSuspiciousCount,
    int ReportIssueCount,
    DateTimeOffset LatestSubmittedAtUtc,
    bool ReviewThresholdReached);

/// <summary>Current weighted evidence for one domain and a bounded event timeline.</summary>
public sealed record AdminFeedbackDomainDetail(
    string Domain,
    WeightedFeedbackSummary Summary,
    IReadOnlyCollection<AdminFeedbackEvent> RecentEvents);

/// <summary>A privacy-safe feedback event without page or reporter identifiers.</summary>
public sealed record AdminFeedbackEvent(
    HipFeedbackType FeedbackType,
    HipFeedbackSource Source,
    ReporterTrustLevel ReporterTrustLevel,
    DateTimeOffset SubmittedAtUtc,
    HipFeedbackReasonCode? ReasonCode);

/// <inheritdoc />
public sealed class AdminFeedbackService(
    IWeightedFeedbackRepository repository,
    IWeightedFeedbackAggregationService aggregationService) : IAdminFeedbackService
{
    private const int MaximumDomains = 100;
    private const int MaximumEvents = 50;
    private static readonly TimeSpan CurrentEvidenceWindow = TimeSpan.FromDays(14);

    /// <inheritdoc />
    public async Task<AdminFeedbackOverview> GetOverviewAsync(CancellationToken cancellationToken)
    {
        var submissions = await repository.ListAsync(cancellationToken).ConfigureAwait(false);
        var currentEvidenceCutoff = DateTimeOffset.UtcNow.Subtract(CurrentEvidenceWindow);
        var domains = submissions
            .Where(item => !string.IsNullOrWhiteSpace(item.Domain))
            .GroupBy(item => item.Domain.Trim().ToLowerInvariant(), StringComparer.OrdinalIgnoreCase)
            .Select(group => new AdminFeedbackDomainRow(
                group.Key,
                group.Count(),
                group.Count(item => item.FeedbackType == HipFeedbackType.LooksSafe),
                group.Count(item => item.FeedbackType == HipFeedbackType.LooksSuspicious),
                group.Count(item => item.FeedbackType == HipFeedbackType.ReportIssue),
                group.Max(item => item.SubmittedAtUtc),
                group.Count(item =>
                    item.SubmittedAtUtc >= currentEvidenceCutoff &&
                    item.FeedbackType is HipFeedbackType.LooksSuspicious or HipFeedbackType.ReportIssue) >= 5))
            .OrderByDescending(item => item.LatestSubmittedAtUtc)
            .ThenBy(item => item.Domain, StringComparer.Ordinal)
            .Take(MaximumDomains)
            .ToArray();

        return new AdminFeedbackOverview(
            submissions.Count,
            submissions.Select(item => item.Domain).Where(domain => !string.IsNullOrWhiteSpace(domain)).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            submissions.Count(item => item.FeedbackType == HipFeedbackType.LooksSafe),
            submissions.Count(item => item.FeedbackType == HipFeedbackType.LooksSuspicious),
            submissions.Count(item => item.FeedbackType == HipFeedbackType.ReportIssue),
            domains);
    }

    /// <inheritdoc />
    public async Task<AdminFeedbackDomainDetail?> GetDomainAsync(string domain, CancellationToken cancellationToken)
    {
        WeightedFeedbackSummary summary;
        try
        {
            summary = await aggregationService.GetSummaryAsync(domain, cancellationToken).ConfigureAwait(false);
        }
        catch (ArgumentException)
        {
            return null;
        }

        var stored = (await repository.ListAsync(cancellationToken).ConfigureAwait(false))
            .Where(item => item.Domain.Equals(summary.Domain, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (stored.Length == 0)
        {
            return null;
        }

        var events = stored
            .OrderByDescending(item => item.SubmittedAtUtc)
            .Take(MaximumEvents)
            .Select(item => new AdminFeedbackEvent(
                item.FeedbackType,
                item.Source,
                item.ReporterTrustLevel,
                item.SubmittedAtUtc,
                item.ReasonCode))
            .ToArray();

        return new AdminFeedbackDomainDetail(summary.Domain, summary, events);
    }
}
