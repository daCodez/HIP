using HIP.Application.Review;
using HIP.Domain.Review;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfAppealRepository(HipRecordStore store) : IAppealRepository
{
    private const string Partition = "appeal";

    public Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, appeal.AppealId, appeal, cancellationToken);

    public Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken) =>
        store.GetAsync<AppealRequest>(Partition, appealId, cancellationToken);

    public Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AppealRequest>(Partition, cancellationToken);
}
