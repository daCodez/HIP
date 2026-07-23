using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public interface IReputationProfileRepository
{
    Task<ReputationProfile?> GetAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken);

    /// <summary>
    /// Lists stored profiles for one reputation subject type.
    /// </summary>
    Task<IReadOnlyCollection<ReputationProfile>> ListAsync(
        ReputationSubjectType targetType,
        CancellationToken cancellationToken);

    Task SaveAsync(ReputationProfile profile, CancellationToken cancellationToken);
}
