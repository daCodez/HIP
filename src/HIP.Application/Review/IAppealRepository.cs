using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAppealRepository
{
    Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken);

    Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken);
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
}
