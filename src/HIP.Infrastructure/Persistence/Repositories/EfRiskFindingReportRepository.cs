using HIP.Application.Reporting;
using HIP.Domain.Reporting;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfRiskFindingReportRepository(
    HipRecordStore store,
    HipDbContext dbContext,
    IHipRecordEncryptor recordEncryptor) : IRiskFindingReportRepository
{
    internal const string Partition = "risk-finding-report";
    internal const string OwnerPartitionPrefix = "risk-finding-report-owner-v1:";
    private readonly OwnerScopedEncryptedRecordQuery ownerRecords = new(dbContext, recordEncryptor);

    public Task AddAsync(RiskFindingReport report, CancellationToken cancellationToken) =>
        ownerRecords.SaveAsync(
            Partition,
            OwnerPartitionPrefix,
            report.ReportId,
            report.ConsumerScopeHash,
            report.DetectedAtUtc,
            report,
            value => value.ReportId,
            value => value.ConsumerScopeHash,
            cancellationToken);

    public Task<IReadOnlyCollection<RiskFindingReport>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<RiskFindingReport>(Partition, cancellationToken);

    public Task<IReadOnlyCollection<RiskFindingReport>> ListByConsumerScopeHashesAsync(
        IReadOnlyCollection<string> consumerScopeHashes,
        int maximumResults,
        CancellationToken cancellationToken) =>
        ownerRecords.ListAsync<RiskFindingReport>(
            OwnerPartitionPrefix,
            consumerScopeHashes,
            maximumResults,
            value => value.ReportId,
            value => value.ConsumerScopeHash,
            value => value.DetectedAtUtc,
            cancellationToken);

    public async Task<int> DeleteExpiredAsync(DateTimeOffset nowUtc, int maximumDeletes, CancellationToken cancellationToken)
    {
        if (maximumDeletes is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximumDeletes));
        var expired = (await store.ListAsync<RiskFindingReport>(Partition, cancellationToken))
            .Where(report => RiskFindingRetention.IsExpired(report, nowUtc))
            .OrderBy(report => report.DetectedAtUtc)
            .Take(maximumDeletes)
            .ToArray();

        var deleted = 0;
        foreach (var report in expired)
        {
            var ownerPartition = OwnerScopedEncryptedRecordQuery.IsPrivacyHash(report.ConsumerScopeHash)
                ? OwnerScopedEncryptedRecordQuery.OwnerPartition(OwnerPartitionPrefix, report.ConsumerScopeHash!)
                : null;
            var rows = dbContext.Records.Where(row =>
                row.Id == report.ReportId &&
                (row.Partition == Partition || ownerPartition != null && row.Partition == ownerPartition));
            dbContext.Records.RemoveRange(rows);
            deleted++;
        }

        if (deleted > 0) await dbContext.SaveChangesAsync(cancellationToken);
        return deleted;
    }
}
