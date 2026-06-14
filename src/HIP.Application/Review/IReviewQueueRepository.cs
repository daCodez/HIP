using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IReviewQueueRepository
{
    Task SaveAsync(ReviewItem item, CancellationToken cancellationToken);

    Task<ReviewItem?> GetAsync(string reviewItemId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ReviewItem>> ListAsync(CancellationToken cancellationToken);
}

public sealed class InMemoryReviewQueueRepository : IReviewQueueRepository
{
    private readonly Dictionary<string, ReviewItem> items = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    public Task SaveAsync(ReviewItem item, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            items[item.ReviewItemId] = item;
        }

        return Task.CompletedTask;
    }

    public Task<ReviewItem?> GetAsync(string reviewItemId, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult(items.GetValueOrDefault(reviewItemId));
        }
    }

    public Task<IReadOnlyCollection<ReviewItem>> ListAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<ReviewItem>>(items.Values.ToArray());
        }
    }
}
