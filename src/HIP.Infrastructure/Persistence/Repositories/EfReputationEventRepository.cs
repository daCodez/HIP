using HIP.Application.Reputation;
using HIP.Domain.Reputation;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfReputationEventRepository(HipRecordStore store) : IReputationEventRepository
{
    public Task AddAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken) =>
        store.SaveAsync(Partition(reputationEvent.TargetType, reputationEvent.TargetId), reputationEvent.EventId, reputationEvent, cancellationToken);

    public Task<IReadOnlyCollection<ReputationEvent>> ListAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken) =>
        store.ListAsync<ReputationEvent>(Partition(targetType, targetId), cancellationToken);

    private static string Partition(ReputationSubjectType targetType, string targetId) =>
        $"reputation-event:{targetType}:{targetId}".ToLowerInvariant();
}
