using System.Collections.Concurrent;
using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public sealed class InMemoryReputationEventRepository : IReputationEventRepository
{
    private readonly ConcurrentDictionary<string, List<ReputationEvent>> _events = new(StringComparer.OrdinalIgnoreCase);

    public Task AddAsync(ReputationEvent reputationEvent, CancellationToken cancellationToken)
    {
        var key = Key(reputationEvent.TargetType, reputationEvent.TargetId);
        var events = _events.GetOrAdd(key, _ => []);

        lock (events)
        {
            events.Add(reputationEvent);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyCollection<ReputationEvent>> ListAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        var key = Key(targetType, targetId);
        if (!_events.TryGetValue(key, out var events))
        {
            return Task.FromResult<IReadOnlyCollection<ReputationEvent>>([]);
        }

        lock (events)
        {
            return Task.FromResult<IReadOnlyCollection<ReputationEvent>>(events.OrderBy(item => item.CreatedAtUtc).ToArray());
        }
    }

    private static string Key(ReputationSubjectType targetType, string targetId) =>
        $"{targetType}:{targetId}".ToLowerInvariant();
}
