using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAppealRepository
{
    const int MaximumOwnerHashCandidates = 9;
    const int MaximumOwnerHistoryItems = 100;

    Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken);

    Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AppealRequest>> ListBySubmitterHashesAsync(
        IReadOnlyCollection<string> submittedByHashes,
        int maximumResults,
        CancellationToken cancellationToken);
}

public sealed class InMemoryAppealRepository : IAppealRepository
{
    private readonly Dictionary<string, AppealRequest> appeals = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();

    public Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            appeals[appeal.AppealId] = appeal;
        }

        return Task.CompletedTask;
    }

    public Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult(appeals.GetValueOrDefault(appealId));
        }
    }

    public Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            return Task.FromResult<IReadOnlyCollection<AppealRequest>>(appeals.Values.ToArray());
        }
    }

    public Task<IReadOnlyCollection<AppealRequest>> ListBySubmitterHashesAsync(
        IReadOnlyCollection<string> submittedByHashes,
        int maximumResults,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submittedByHashes);
        if (submittedByHashes.Count is < 1 or > IAppealRepository.MaximumOwnerHashCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(submittedByHashes));
        }
        if (maximumResults is < 1 or > IAppealRepository.MaximumOwnerHistoryItems)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResults));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var candidates = submittedByHashes.ToHashSet(StringComparer.Ordinal);
        lock (gate)
        {
            IReadOnlyCollection<AppealRequest> matches = appeals.Values
                .Where(appeal => candidates.Contains(appeal.SubmittedByHash))
                .OrderByDescending(appeal => appeal.UpdatedAtUtc)
                .ThenBy(appeal => appeal.AppealId, StringComparer.Ordinal)
                .Take(maximumResults)
                .ToArray();
            return Task.FromResult(matches);
        }
    }
}
