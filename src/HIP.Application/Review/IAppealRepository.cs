using HIP.Domain.Review;

namespace HIP.Application.Review;

public interface IAppealRepository
{
    Task SaveAsync(AppealRequest appeal, CancellationToken cancellationToken);

    Task<AppealRequest?> GetAsync(string appealId, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<AppealRequest>> ListAsync(CancellationToken cancellationToken);
}
