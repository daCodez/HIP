using HIP.Domain.Reporting;

namespace HIP.Application.Reporting;

public interface IRiskFindingReportRepository
{
    const int MaximumOwnerHashCandidates = 9;
    const int MaximumOwnerHistoryItems = 100;

    Task AddAsync(RiskFindingReport report, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<RiskFindingReport>> ListAsync(CancellationToken cancellationToken);

    Task<IReadOnlyCollection<RiskFindingReport>> ListByConsumerScopeHashesAsync(
        IReadOnlyCollection<string> consumerScopeHashes,
        int maximumResults,
        CancellationToken cancellationToken);

    Task<int> DeleteExpiredAsync(DateTimeOffset nowUtc, int maximumDeletes, CancellationToken cancellationToken);
}
