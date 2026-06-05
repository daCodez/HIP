using HIP.Application.Reputation;

namespace HIP.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF-backed weighted feedback repository using HIP's JSON record store.
/// </summary>
public sealed class EfWeightedFeedbackRepository(HipRecordStore store) : IWeightedFeedbackRepository
{
    private const string Partition = "weighted-feedback";

    /// <inheritdoc />
    public Task SaveAsync(WeightedFeedbackSubmission submission, CancellationToken cancellationToken)
    {
        var id = $"{submission.Domain}:{submission.SubmittedAtUtc:O}:{Guid.NewGuid():N}";
        return store.SaveAsync(Partition, id, submission, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<WeightedFeedbackSubmission>> ListRecentAsync(string domain, DateTimeOffset sinceUtc, CancellationToken cancellationToken)
    {
        var submissions = await store.ListAsync<WeightedFeedbackSubmission>(Partition, cancellationToken);
        return submissions
            .Where(item => item.Domain.Equals(domain, StringComparison.OrdinalIgnoreCase) && item.SubmittedAtUtc >= sinceUtc)
            .OrderBy(item => item.SubmittedAtUtc)
            .ToArray();
    }
}
