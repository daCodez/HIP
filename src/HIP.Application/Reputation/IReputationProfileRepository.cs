using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public interface IReputationProfileRepository
{
    Task<ReputationProfile?> GetAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken);

    Task SaveAsync(ReputationProfile profile, CancellationToken cancellationToken);
}
