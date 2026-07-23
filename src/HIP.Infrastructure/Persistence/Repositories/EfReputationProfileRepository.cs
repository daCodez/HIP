using HIP.Application.Reputation;
using HIP.Domain.Reputation;

namespace HIP.Infrastructure.Persistence.Repositories;

public sealed class EfReputationProfileRepository(HipRecordStore store) : IReputationProfileRepository
{
    public Task<ReputationProfile?> GetAsync(ReputationSubjectType targetType, string targetId, CancellationToken cancellationToken) =>
        store.GetAsync<ReputationProfile>("reputation-profile", Key(targetType, targetId), cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<ReputationProfile>> ListAsync(
        ReputationSubjectType targetType,
        CancellationToken cancellationToken) =>
        (await store.ListAsync<ReputationProfile>("reputation-profile", cancellationToken).ConfigureAwait(false))
            .Where(profile => profile.TargetType == targetType)
            .ToArray();

    public Task SaveAsync(ReputationProfile profile, CancellationToken cancellationToken) =>
        store.SaveAsync("reputation-profile", Key(profile.TargetType, profile.TargetId), profile, cancellationToken);

    private static string Key(ReputationSubjectType targetType, string targetId) =>
        $"{targetType}:{targetId}".ToLowerInvariant();
}
