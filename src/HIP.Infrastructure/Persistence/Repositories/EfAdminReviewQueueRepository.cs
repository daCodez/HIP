using HIP.Application.Review;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed admin review queue repository using HIP's JSON record store.
/// </summary>
public sealed class EfAdminReviewQueueRepository(HipRecordStore store) : IAdminReviewQueueRepository
{
    private const string Partition = "admin-review-queue";

    /// <inheritdoc />
    public Task SaveAsync(AdminReviewQueueItem item, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition, item.ReviewId, item, cancellationToken);

    /// <inheritdoc />
    public Task<AdminReviewQueueItem?> GetAsync(string reviewId, CancellationToken cancellationToken) =>
        store.GetAsync<AdminReviewQueueItem>(Partition, reviewId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyCollection<AdminReviewQueueItem>> ListAsync(CancellationToken cancellationToken) =>
        store.ListAsync<AdminReviewQueueItem>(Partition, cancellationToken);
}
