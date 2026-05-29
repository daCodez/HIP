using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public interface IRiskFindingReportRepository
{
    Task AddAsync(RiskFindingReport report, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<RiskFindingReport>> ListAsync(CancellationToken cancellationToken);
}
