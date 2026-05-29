using System.Collections.Concurrent;
using HIP.Domain.Reputation;

namespace HIP.Application.Reputation;

public sealed class InMemoryReputationProfileRepository : IReputationProfileRepository
{
    private readonly ConcurrentDictionary<string, ReputationProfile> _profiles = new(StringComparer.OrdinalIgnoreCase);

    public Task<ReputationProfile?> GetAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken)
    {
        _profiles.TryGetValue(Key(targetType, targetId), out var profile);
        return Task.FromResult(profile);
    }

    public Task SaveAsync(ReputationProfile profile, CancellationToken cancellationToken)
    {
        _profiles[Key(profile.TargetType, profile.TargetId)] = profile;
        return Task.CompletedTask;
    }

    private static string Key(ReputationSubjectType targetType, string targetId) =>
        $"{targetType}:{targetId}".ToLowerInvariant();
}
