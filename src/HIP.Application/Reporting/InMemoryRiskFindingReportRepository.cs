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
}
