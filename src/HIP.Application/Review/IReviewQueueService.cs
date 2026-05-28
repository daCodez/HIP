using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReviewQueueService
{
    ReviewItem Create(ReviewItem item);

    IReadOnlyCollection<ReviewItem> List();

    ReviewItem? Get(string reviewItemId);

    ReviewItem Assign(string reviewItemId, string assignedTo, string actorId);

    ReviewItem UpdateStatus(string reviewItemId, ReviewStatus status, string actorId, string? reason = null);

    ReviewItem Approve(string reviewItemId, string actorId, string reason);

    ReviewItem Reject(string reviewItemId, string actorId, string reason);

    ReviewItem RequestMoreInfo(string reviewItemId, string actorId, string reason);

    ReviewItem Close(string reviewItemId, string actorId, string reason);
}
