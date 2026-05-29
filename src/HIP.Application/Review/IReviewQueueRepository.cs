using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReviewQueueRepository
{
    Task SaveAsync(ReviewItem item, CancellationToken cancellationToken);

    Task<ReviewItem?> GetAsync(string reviewItemId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ReviewItem>> ListAsync(CancellationToken cancellationToken);
}
