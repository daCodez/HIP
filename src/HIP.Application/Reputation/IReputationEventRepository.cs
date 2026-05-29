using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public interface IReputationEventRepository
{
    Task AddAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken);

    Task<IReadOnlyCollection<ReputationEvent>> ListAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken);
}
