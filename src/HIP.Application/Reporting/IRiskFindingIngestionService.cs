using HIP.Domain.Reporting;
using HIP.Domain.SelfHealing;

namespace HIP.Application.Reporting;

public interface IRiskFindingIngestionService
{
    Task<RiskFindingIngestionResponse> IngestAsync(RiskFindingReport report, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<RiskFindingReport>> ListReportsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyCollection<PatternCluster>> DetectPatternsAsync(CancellationToken cancellationToken);
}
