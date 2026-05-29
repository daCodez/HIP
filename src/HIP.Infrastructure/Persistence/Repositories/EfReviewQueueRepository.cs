using HIP.Application.Review;
using HIP.Domain.Review;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfReviewQueueRepository(HipRecordStore store) : IReviewQueueRepository
{
    private const string Partition = "review-item";

    public Task SaveAsync(ReviewItem item, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, item.ReviewItemId, item, cancellationToken);

    public Task<ReviewItem?> GetAsync(string reviewItemId, CancellationToken cancellationToken) =>
        store.GetAsync<ReviewItem>(Partition, reviewItemId, cancellationToken);

    public Task<IReadOnlyCollection<ReviewItem>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<ReviewItem>(Partition, cancellationToken);
}
