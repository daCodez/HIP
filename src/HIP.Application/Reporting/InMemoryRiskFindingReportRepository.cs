using System.Collections.Concurrent;
using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public sealed class InMemoryRiskFindingReportRepository : IRiskFindingReportRepository
{
    private readonly ConcurrentDictionary<string, RiskFindingReport> _reports = new(StringComparer.OrdinalIgnoreCase);

    public Task AddAsync(RiskFindingReport report, CancellationToken cancellationToken)
    {
        _reports[report.ReportId] = report;
        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<RiskFindingReport>> ListAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyCollection<RiskFindingReport>>(_reports.Values.OrderByDescending(report => report.DetectedAtUtc).ToArray());

    public Task<IReadOnlyCollection<RiskFindingReport>> ListByConsumerScopeHashesAsync(
        IReadOnlyCollection<string> consumerScopeHashes,
        int maximumResults,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(consumerScopeHashes);
        if (consumerScopeHashes.Count is < 1 or > IRiskFindingReportRepository.MaximumOwnerHashCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(consumerScopeHashes));
        }
        if (maximumResults is < 1 or > IRiskFindingReportRepository.MaximumOwnerHistoryItems)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResults));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var candidates = consumerScopeHashes.ToHashSet(StringComparer.Ordinal);
        IReadOnlyCollection<RiskFindingReport> reports = _reports.Values
            .Where(report =>
                report.ConsumerScopeHash is not null &&
                candidates.Contains(report.ConsumerScopeHash))
            .OrderByDescending(report => report.DetectedAtUtc)
            .ThenBy(report => report.ReportId, StringComparer.Ordinal)
            .Take(maximumResults)
            .ToArray();
        return Task.FromResult(reports);
    }

    public Task<int> DeleteExpiredAsync(DateTimeOffset nowUtc, int maximumDeletes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumDeletes is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumDeletes));
        var expired = _reports.Values
            .Where(report => RiskFindingRetention.IsExpired(report, nowUtc))
            .OrderBy(report => report.DetectedAtUtc)
            .Take(maximumDeletes)
            .Select(report => report.ReportId)
            .ToArray();
        var deleted = expired.Count(id => _reports.TryRemove(id, out _));
        return Task.FromResult(deleted);
    }
}
