using HIP.Application.Review;
using HIP.Domain.Review;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfAppealRepository(
    HipRecordStore store,
    HipDbContext dbContext,
    IHipRecordEncryptor recordEncryptor) : IAppealRepository
{
    internal const string Partition = "appeal";
    internal const string OwnerPartitionPrefix = "appeal-owner-v1:";
    private readonly OwnerScopedEncryptedRecordQuery ownerRecords = new(dbContext, recordEncryptor);

    public Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken) =>
        ownerRecords.SaveAsync(
            Partition,
            OwnerPartitionPrefix,
            appeal.AppealId,
            appeal.SubmittedByHash,
            appeal.UpdatedAtUtc,
            appeal,
            value => value.AppealId,
            value => value.SubmittedByHash,
            cancellationToken);

    public Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken) =>
        store.GetAsync<AppealRequest>(Partition, appealId, cancellationToken);

    public Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AppealRequest>(Partition, cancellationToken);

    public Task<IReadOnlyCollection<AppealRequest>> ListBySubmitterHashesAsync(
        IReadOnlyCollection<string> submittedByHashes,
        int maximumResults,
        CancellationToken cancellationToken) =>
        ownerRecords.ListAsync<AppealRequest>(
            OwnerPartitionPrefix,
            submittedByHashes,
            maximumResults,
            value => value.AppealId,
            value => value.SubmittedByHash,
            value => value.UpdatedAtUtc,
            cancellationToken);
}
