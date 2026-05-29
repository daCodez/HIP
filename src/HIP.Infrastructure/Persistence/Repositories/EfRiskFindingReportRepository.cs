using HIP.Application.Reporting;
using HIP.Domain.Reporting;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRiskFindingReportRepository(HipRecordStore store) : IRiskFindingReportRepository
{
    private const string Partition = "risk-finding-report";

    public Task AddAsync(RiskFindingReport report, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, report.ReportId, report, cancellationToken);

    public Task<IReadOnlyCollection<RiskFindingReport>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<RiskFindingReport>(Partition, cancellationToken);
}
